interface AppStateScreenProps {
  title: string;
  message: string;
  tone?: "neutral" | "warning" | "danger";
}

export function AppStateScreen({
  title,
  message,
  tone = "neutral",
}: AppStateScreenProps) {
  return (
    <div className={`state-screen state-screen--${tone}`}>
      <div className="state-screen__panel">
        <p className="state-screen__eyebrow">AILA Console</p>
        <h1>{title}</h1>
        <p>{message}</p>
      </div>
    </div>
  );
}
