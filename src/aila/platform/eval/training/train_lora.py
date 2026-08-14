"""TRL + PEFT QLoRA SFT -> DPO -> merge pipeline (issue #158).

Runnable module:

    python -m aila.platform.eval.training.train_lora

Reads the corpus produced by
:func:`aila.platform.eval.corpus.export_corpus` (``sft.jsonl`` +
``dpo.jsonl`` under ``platform.corpus_output_dir``), then:

1. Loads the base HF model (``platform.training_base_model``) under a
   4-bit ``BitsAndBytesConfig``.
2. Runs ``trl.SFTTrainer`` on ``sft.jsonl`` behind a
   ``peft.LoraConfig`` (r / alpha / dropout from platform config).
3. Runs ``trl.DPOTrainer`` on ``dpo.jsonl`` starting from the SFT
   LoRA adapter (beta=0.1).
4. Merges the LoRA adapter into the base weights via
   ``model.merge_and_unload()`` and writes the checkpoint to
   ``platform.training_output_dir``.

Every heavy dependency (torch, transformers, trl, peft, datasets,
accelerate, bitsandbytes) is imported LAZILY inside
:func:`train_lora_from_corpus` so importing this module never requires
them -- the ``[training]`` optional extra is the only place the
version pins live. If the extra is missing, the CLI raises a clear
``ImportError`` with a ``pip install .[training]`` remediation string.
If ``platform.training_base_model`` is empty, the CLI raises a clear
``ValueError`` telling the operator which config key to set. Both
failure modes surface BEFORE any GPU work happens.
"""
from __future__ import annotations

import asyncio
import logging
import sys
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.exc import SQLAlchemyError

from aila.config import _resolve_project_path
from aila.platform.config import PlatformConfigSchema
from aila.platform.eval.corpus import resolve_corpus_output_dir
from aila.storage.registry import ConfigRegistry

__all__ = ["TrainingParams", "main", "train_lora_from_corpus"]

_log = logging.getLogger(__name__)

_INSTALL_HINT: str = (
    "The LoRA fine-tune pipeline requires the '[training]' optional extra. "
    "Install it on the GPU host with `pip install .[training]`."
)


@dataclass(frozen=True, slots=True)
class TrainingParams:
    """Resolved config for a single train-and-merge run."""

    base_model: str
    corpus_dir: Path
    output_dir: Path
    lora_r: int
    lora_alpha: int
    lora_dropout: float
    sft_path: Path
    dpo_path: Path


async def _load_params() -> TrainingParams:
    """Resolve every knob through :class:`ConfigRegistry`."""
    schema = PlatformConfigSchema()
    registry = ConfigRegistry()

    base_model = await _read_str(registry, "training_base_model", schema.training_base_model)
    if not base_model.strip():
        raise ValueError(
            "platform.training_base_model is empty -- set it via "
            "`PUT /config/platform/training_base_model` (or the env var "
            "AILA_PLATFORM_TRAINING_BASE_MODEL) to the HuggingFace id of the "
            "base model you want to fine-tune (e.g. "
            "'meta-llama/Meta-Llama-3.1-8B-Instruct').",
        )
    corpus_raw = await _read_str(registry, "corpus_output_dir", schema.corpus_output_dir)
    output_raw = await _read_str(registry, "training_output_dir", schema.training_output_dir)
    lora_r = await _read_int(registry, "training_lora_r", schema.training_lora_r)
    lora_alpha = await _read_int(registry, "training_lora_alpha", schema.training_lora_alpha)
    lora_dropout = await _read_float(
        registry, "training_lora_dropout", schema.training_lora_dropout,
    )

    corpus_dir = resolve_corpus_output_dir(corpus_raw)
    output_dir = (
        _resolve_project_path(output_raw)
        if output_raw
        else _resolve_project_path("data/lora_out")
    )
    sft_path = corpus_dir / "sft.jsonl"
    dpo_path = corpus_dir / "dpo.jsonl"

    return TrainingParams(
        base_model=base_model.strip(),
        corpus_dir=corpus_dir,
        output_dir=output_dir,
        lora_r=lora_r,
        lora_alpha=lora_alpha,
        lora_dropout=lora_dropout,
        sft_path=sft_path,
        dpo_path=dpo_path,
    )


def train_lora_from_corpus(params: TrainingParams) -> Path:
    """Run SFT -> DPO -> merge from ``params`` and return the checkpoint dir.

    Every heavy import lives INSIDE this function so an operator (or
    the API process) can `import aila.platform.eval.training.train_lora`
    without pulling in torch. Callers that want to run without a GPU
    host should never call this function -- there is no meaningful
    CPU fallback for QLoRA.
    """
    if not params.sft_path.exists():
        raise FileNotFoundError(
            f"SFT corpus missing at {params.sft_path}. Run the "
            "corpus export first (POST /platform/eval/corpus/export or "
            "the run_corpus_export platform task).",
        )
    if not params.dpo_path.exists():
        raise FileNotFoundError(
            f"DPO corpus missing at {params.dpo_path}. Run the "
            "corpus export first (POST /platform/eval/corpus/export or "
            "the run_corpus_export platform task).",
        )
    params.output_dir.mkdir(parents=True, exist_ok=True)
    sft_adapter_dir = params.output_dir / "sft_adapter"
    dpo_adapter_dir = params.output_dir / "dpo_adapter"
    merged_dir = params.output_dir / "merged"

    try:
        import torch  # type: ignore[import-not-found]
        from datasets import load_dataset  # type: ignore[import-not-found]
        from peft import LoraConfig, PeftModel  # type: ignore[import-not-found]
        from transformers import (  # type: ignore[import-not-found]
            AutoModelForCausalLM,
            AutoTokenizer,
            BitsAndBytesConfig,
        )
        from trl import (  # type: ignore[import-not-found]
            DPOConfig,
            DPOTrainer,
            SFTConfig,
            SFTTrainer,
        )
    except ImportError as exc:  # pragma: no cover -- deps optional
        raise ImportError(f"{_INSTALL_HINT} Missing dependency: {exc}") from exc

    _log.info(
        "train_lora start base=%s sft=%s dpo=%s out=%s r=%d alpha=%d dropout=%.3f",
        params.base_model,
        params.sft_path,
        params.dpo_path,
        params.output_dir,
        params.lora_r,
        params.lora_alpha,
        params.lora_dropout,
    )

    # ------------------------------------------------------------------
    # 1. Load the base model under 4-bit QLoRA.
    # ------------------------------------------------------------------
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )
    tokenizer = AutoTokenizer.from_pretrained(params.base_model, use_fast=True)
    if tokenizer.pad_token is None:
        # Common HF gotcha: many base checkpoints omit the pad token;
        # QLoRA + DataCollatorForCompletion needs one, so re-use eos.
        tokenizer.pad_token = tokenizer.eos_token
    base_model = AutoModelForCausalLM.from_pretrained(
        params.base_model,
        quantization_config=bnb_config,
        device_map="auto",
        torch_dtype=torch.bfloat16,
    )

    lora_config = LoraConfig(
        r=params.lora_r,
        lora_alpha=params.lora_alpha,
        lora_dropout=params.lora_dropout,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules="all-linear",
    )

    # ------------------------------------------------------------------
    # 2. Supervised fine-tune on sft.jsonl (ShareGPT ``messages`` shape).
    # ------------------------------------------------------------------
    sft_dataset = load_dataset(
        "json",
        data_files=str(params.sft_path),
        split="train",
    )
    sft_config = SFTConfig(
        output_dir=str(sft_adapter_dir),
        num_train_epochs=1,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=8,
        learning_rate=2e-4,
        lr_scheduler_type="cosine",
        warmup_ratio=0.03,
        logging_steps=10,
        save_strategy="epoch",
        bf16=True,
        gradient_checkpointing=True,
        report_to=[],
    )
    sft_trainer = SFTTrainer(
        model=base_model,
        args=sft_config,
        train_dataset=sft_dataset,
        peft_config=lora_config,
        tokenizer=tokenizer,
    )
    sft_trainer.train()
    sft_trainer.save_model(str(sft_adapter_dir))
    _log.info("train_lora SFT stage complete -> %s", sft_adapter_dir)

    # ------------------------------------------------------------------
    # 3. Direct preference optimization on dpo.jsonl starting from the
    #    SFT adapter. DPO trains a new adapter on top of the SFT one
    #    (peft handles the composition) so the checkpoint we merge at
    #    the end reflects BOTH stages of learning.
    # ------------------------------------------------------------------
    dpo_dataset = load_dataset(
        "json",
        data_files=str(params.dpo_path),
        split="train",
    )
    # DPOTrainer expects (prompt, chosen, rejected) string columns. The
    # corpus writes ``prompt`` as EITHER a string OR a list of message
    # dicts; normalize the list shape to a string so the trainer can
    # tokenize it uniformly.
    dpo_dataset = dpo_dataset.map(_normalize_dpo_prompt)
    # Load the SFT adapter into a PeftModel so DPO trains the deltas on
    # top of the SFT-tuned base (recommended TRL flow, arxiv 2607.10601).
    peft_sft_model = PeftModel.from_pretrained(base_model, str(sft_adapter_dir))
    dpo_config = DPOConfig(
        output_dir=str(dpo_adapter_dir),
        num_train_epochs=1,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=8,
        learning_rate=5e-6,
        lr_scheduler_type="cosine",
        warmup_ratio=0.03,
        logging_steps=10,
        save_strategy="epoch",
        bf16=True,
        gradient_checkpointing=True,
        beta=0.1,
        report_to=[],
    )
    dpo_trainer = DPOTrainer(
        model=peft_sft_model,
        args=dpo_config,
        train_dataset=dpo_dataset,
        tokenizer=tokenizer,
    )
    dpo_trainer.train()
    dpo_trainer.save_model(str(dpo_adapter_dir))
    _log.info("train_lora DPO stage complete -> %s", dpo_adapter_dir)

    # ------------------------------------------------------------------
    # 4. Merge the DPO-updated LoRA back into the base weights and save
    #    the standalone HF checkpoint the operator loads at serve time.
    # ------------------------------------------------------------------
    merged = peft_sft_model.merge_and_unload()
    merged.save_pretrained(str(merged_dir))
    tokenizer.save_pretrained(str(merged_dir))
    _log.info("train_lora merge complete -> %s", merged_dir)
    return merged_dir


def _normalize_dpo_prompt(example: dict) -> dict:
    """Coerce the ``prompt`` column to a string for TRL's DPO tokenizer.

    The corpus emits ``prompt`` as EITHER a plain string OR a list of
    ``{role, content}`` dicts (the SftMessage shape). TRL's DPOTrainer
    wants a single tokenizable string, so we join the message contents
    with newlines and prepend the role name for readability.
    """
    prompt = example.get("prompt")
    if isinstance(prompt, str):
        return example
    if isinstance(prompt, list):
        parts: list[str] = []
        for message in prompt:
            if not isinstance(message, dict):
                continue
            role = str(message.get("role") or "user")
            content = message.get("content") or ""
            if isinstance(content, list):
                content = "\n".join(
                    b.get("text") if isinstance(b, dict) else str(b) for b in content
                )
            parts.append(f"[{role}]\n{content}")
        example = dict(example)
        example["prompt"] = "\n\n".join(parts)
    return example


async def _read_str(registry: ConfigRegistry, key: str, default: str) -> str:
    try:
        raw = await registry.get("platform", key)
    except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError):
        return default
    return default if raw is None else str(raw)


async def _read_int(registry: ConfigRegistry, key: str, default: int) -> int:
    try:
        raw = await registry.get("platform", key)
    except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError):
        return default
    if raw is None:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


async def _read_float(registry: ConfigRegistry, key: str, default: float) -> float:
    try:
        raw = await registry.get("platform", key)
    except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError):
        return default
    if raw is None:
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default


def main() -> int:
    """CLI entrypoint. Returns the process exit code."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        params = asyncio.run(_load_params())
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        merged_dir = train_lora_from_corpus(params)
    except (FileNotFoundError, ImportError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    print(str(merged_dir))
    return 0


if __name__ == "__main__":  # pragma: no cover -- CLI entry
    raise SystemExit(main())
