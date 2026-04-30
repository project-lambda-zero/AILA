import type { BlobResponsePayload } from "@platform/api/http";

export function saveBlobResponse(payload: BlobResponsePayload, fallbackFileName: string) {
  const objectUrl = URL.createObjectURL(payload.blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = payload.fileName ?? fallbackFileName;
  anchor.click();
  URL.revokeObjectURL(objectUrl);
}
