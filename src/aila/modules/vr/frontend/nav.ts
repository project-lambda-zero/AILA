export const nav = [
  {
    id: "vr.projects",
    slot: "sidebar.main" as const,
    label: "Vuln Research",
    to: "/vr",
    order: 70,
    description: "N-day vulnerability research projects",
  },
  {
    id: "vr.investigations",
    slot: "sidebar.main" as const,
    label: "Investigations",
    to: "/vr/investigations",
    order: 71,
    description: "Hypothesis-driven investigations across targets",
  },
];
