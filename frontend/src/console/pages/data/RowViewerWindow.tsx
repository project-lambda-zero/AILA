/** The DataPage per-row floating viewer (PageRowViewer): a page-local
 * <ConsoleWindow kind="floater"> whose open/minimized/fullscreen state the
 * DataPage owns. */

import { useState } from "react";
import type { JSX } from "react";

import { ConsoleWindow } from "../../window";
import type { DataRow, PageRowViewer } from "./types";

export interface RowViewerWindowProps {
  viewer: PageRowViewer;
  row: DataRow;
  windowId: string;
  onClose: () => void;
}

export function RowViewerWindow(props: RowViewerWindowProps): JSX.Element {
  const { viewer, row, windowId, onClose } = props;
  const [minimized, setMinimized] = useState(false);
  const [fullscreen, setFullscreen] = useState(false);
  const [focused, setFocused] = useState(true);
  return (
    <ConsoleWindow
      id={`${windowId}:viewer`}
      kind="floater"
      title={viewer.title(row)}
      initialRect={{ x: 160, y: 120, w: 880, h: 560 }}
      minSize={{ w: 480, h: 320 }}
      isFullscreen={fullscreen}
      isMinimized={minimized}
      isFocused={focused}
      onFocus={() => setFocused(true)}
      onClose={onClose}
      onMinimize={() => setMinimized((m) => !m)}
      onToggleFullscreen={() => setFullscreen((f) => !f)}
    >
      {viewer.render(row, onClose)}
    </ConsoleWindow>
  );
}
