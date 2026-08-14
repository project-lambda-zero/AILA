"""LoRA fine-tune pipeline (issue #158).

Consumes the trajectory-mined SFT + DPO corpus written by
:func:`aila.platform.eval.corpus.export_corpus` and produces a merged
LoRA checkpoint via TRL + PEFT. Heavy deps (torch / transformers / trl
/ peft / datasets / accelerate / bitsandbytes) are declared in the
``[training]`` optional extra and imported LAZILY inside
:func:`train_lora_from_corpus` so importing this package on the API
process is free of the training stack.

Documented prerequisite: a GPU host with CUDA and enough VRAM for the
configured 4-bit QLoRA + DPO run. The training-CLI entrypoint
(``python -m aila.platform.eval.training.train_lora``) fails fast with
a clear ImportError if the extra is not installed and with a clear
ValueError if ``platform.training_base_model`` is empty.
"""
from __future__ import annotations

__all__: list[str] = ["train_lora_from_corpus"]


def __getattr__(name: str):
    """Defer the train_lora import so this package is heavy-dep-free."""
    if name == "train_lora_from_corpus":
        from .train_lora import train_lora_from_corpus as _fn
        return _fn
    raise AttributeError(f"module 'aila.platform.eval.training' has no attribute {name!r}")
