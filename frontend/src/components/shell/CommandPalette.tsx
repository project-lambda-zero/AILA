import { useState, useEffect, useMemo } from "react";
import { useNavigate } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Desktop } from "@phosphor-icons/react/dist/csr/Desktop";
import { Bug } from "@phosphor-icons/react/dist/csr/Bug";
import { ShieldWarning } from "@phosphor-icons/react/dist/csr/ShieldWarning";
import { ClipboardText } from "@phosphor-icons/react/dist/csr/ClipboardText";
import { ArrowSquareOut } from "@phosphor-icons/react/dist/csr/ArrowSquareOut";
import { ClockCounterClockwise } from "@phosphor-icons/react/dist/csr/ClockCounterClockwise";
import { MagnifyingGlass } from "@phosphor-icons/react/dist/csr/MagnifyingGlass";
import { Crosshair } from "@phosphor-icons/react/dist/csr/Crosshair";
import { Gauge } from "@phosphor-icons/react/dist/csr/Gauge";
import { ChartBar } from "@phosphor-icons/react/dist/csr/ChartBar";
import { Key } from "@phosphor-icons/react/dist/csr/Key";
import { FileText } from "@phosphor-icons/react/dist/csr/FileText";
import { X } from "@phosphor-icons/react/dist/csr/X";

import {
  Command,
  CommandDialog,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
  CommandShortcut,
  CommandSeparator,
} from "@/components/ui/command";
import { authorizedRequestJson } from "@platform/api/http";
import { useAuthStore } from "@platform/auth/useAuthStore";
import { useTheme } from "@/providers/ThemeProvider";
import { useRecentlyViewed } from "@/hooks/useRecentlyViewed";
import { useSearchHistory } from "@/hooks/useSearchHistory";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface SearchResult {
  id: string;
  type: string;
  label: string;
  url: string;
  metadata?: Record<string, unknown>;
}

interface DataEnvelope<T> {
  data: T;
  meta?: unknown;
}

interface NavCommand {
  id: string;
  label: string;
  action: () => void;
  shortcut?: string;
  icon?: React.ReactNode;
}

// ---------------------------------------------------------------------------
// Static type metadata
// ---------------------------------------------------------------------------

const TYPE_LABELS: Record<string, string> = {
  system: "Systems",
  finding: "Findings",
  cve: "CVEs",
  session: "Sessions",
};

const TYPE_ICONS: Record<string, React.ReactNode> = {
  system: <Desktop size={16} />,
  finding: <Bug size={16} />,
  cve: <ShieldWarning size={16} />,
  session: <ClipboardText size={16} />,
};

function getTypeIcon(type: string): React.ReactNode {
  return TYPE_ICONS[type] ?? <ArrowSquareOut size={16} />;
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const navigate = useNavigate();
  const { cycleTheme } = useTheme();
  const { items: recentItems } = useRecentlyViewed();
  const { items: searchHistory, addSearch, clearHistory } = useSearchHistory();

  // Dual mode detection (D-09)
  const isCommandMode = query.startsWith(">");
  const searchQuery = isCommandMode ? query.slice(1).trimStart() : query;

  // ---------------------------------------------------------------------------
  // Listen for open-command-palette event from AppHeader (Plan 02 contract)
  // ---------------------------------------------------------------------------
  useEffect(() => {
    function handleOpen() {
      setOpen((prev) => !prev);
    }
    window.addEventListener("open-command-palette", handleOpen);
    return () => window.removeEventListener("open-command-palette", handleOpen);
  }, []);

  // Reset query when dialog closes
  useEffect(() => {
    if (!open) {
      setQuery("");
    }
  }, [open]);

  // ---------------------------------------------------------------------------
  // Server-side search (search mode only, D-10)
  // shouldFilter={false} — server handles filtering
  // ---------------------------------------------------------------------------
  const searchResultsQuery = useQuery({
    queryKey: ["search", searchQuery],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<SearchResult[]>>(
        `/search?q=${encodeURIComponent(searchQuery)}&limit=20`,
      ),
    enabled: searchQuery.length >= 2 && !isCommandMode,
    staleTime: 10_000,
  });

  // Group results by entity type
  const groupedResults = useMemo(() => {
    const results = searchResultsQuery.data?.data ?? [];
    const groups: Record<string, SearchResult[]> = {};
    for (const item of results) {
      if (!groups[item.type]) {
        groups[item.type] = [];
      }
      groups[item.type].push(item);
    }
    return groups;
  }, [searchResultsQuery.data]);

  // ---------------------------------------------------------------------------
  // Navigation commands (command mode)
  // ---------------------------------------------------------------------------
  const navCommands: NavCommand[] = useMemo(
    () => [
      {
        id: "go-dashboard",
        label: "Go to Dashboard",
        action: () => navigate("/"),
        shortcut: "G D",
        icon: <Gauge size={16} />,
      },
      {
        id: "go-systems",
        label: "Go to Systems",
        action: () => navigate("/systems"),
        shortcut: "G S",
        icon: <Desktop size={16} />,
      },
      {
        id: "go-findings",
        label: "Go to Findings",
        action: () => navigate("/findings"),
        shortcut: "G F",
        icon: <Bug size={16} />,
      },
      {
        id: "go-scans",
        label: "Go to Scan Center",
        action: () => navigate("/scans"),
        shortcut: "G C",
        icon: <Crosshair size={16} />,
      },
      {
        id: "go-radar",
        label: "Go to Radar",
        action: () => navigate("/radar"),
        icon: <ChartBar size={16} />,
      },
      {
        id: "go-viz",
        label: "Go to Data Visualization",
        action: () => navigate("/viz"),
        icon: <ChartBar size={16} />,
      },
      {
        id: "go-settings",
        label: "Go to Settings",
        action: () => navigate("/settings"),
        shortcut: "G E",
        icon: <ClipboardText size={16} />,
      },
      {
        id: "go-sessions",
        label: "Go to Sessions",
        action: () => navigate("/settings/sessions"),
        icon: <ClipboardText size={16} />,
      },
      {
        id: "go-audit",
        label: "Go to Audit Logs",
        action: () => navigate("/admin/audit"),
        icon: <FileText size={16} />,
      },
      {
        id: "go-api-keys",
        label: "Go to API Keys",
        action: () => navigate("/admin/api-keys"),
        icon: <Key size={16} />,
      },
      {
        id: "cycle-theme",
        label: "Cycle Theme",
        action: () => cycleTheme(),
      },
      {
        id: "sign-out",
        label: "Sign Out",
        action: () => {
          useAuthStore.getState().logout();
          navigate("/login");
        },
      },
    ],
    [navigate, cycleTheme],
  );

  // Filter commands by search query in command mode
  const filteredCommands = useMemo(() => {
    if (!searchQuery) return navCommands;
    const lower = searchQuery.toLowerCase();
    return navCommands.filter((cmd) =>
      cmd.label.toLowerCase().includes(lower),
    );
  }, [navCommands, searchQuery]);

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  function closeAndNavigate(url: string) {
    navigate(url);
    setOpen(false);
  }

  function executeCommand(cmd: NavCommand) {
    cmd.action();
    setOpen(false);
  }

  function selectSearchResult(result: SearchResult) {
    addSearch(searchQuery);
    closeAndNavigate(result.url);
  }

  function replaySearch(historyQuery: string) {
    setQuery(historyQuery);
  }

  // ---------------------------------------------------------------------------
  // Derived state
  // ---------------------------------------------------------------------------

  const hasSearchResults = Object.keys(groupedResults).length > 0;
  const isSearchLoading =
    searchResultsQuery.isFetching && searchQuery.length >= 2;
  const isEmptyQuery = query === "";
  const placeholderText = isCommandMode
    ? "> Command..."
    : "Search systems, findings, CVEs...";

  return (
    <CommandDialog
      open={open}
      onOpenChange={(nextOpen) => setOpen(nextOpen)}
    >
      {/*
        CRITICAL: shouldFilter={false} when in search mode.
        Server-side results are already filtered.
        In command mode we use client-side filtering via filteredCommands.
      */}
      <Command shouldFilter={false}>
        <CommandInput
          placeholder={placeholderText}
          value={query}
          onValueChange={setQuery}
        />
        <CommandList>

          {/* ----------------------------------------------------------------
              EMPTY QUERY STATE — Recently Viewed + Search History
          ---------------------------------------------------------------- */}
          {!isCommandMode && isEmptyQuery && (
            <>
              {recentItems.length > 0 && (
                <CommandGroup heading="Recently Viewed">
                  {recentItems.map((item) => (
                    <CommandItem
                      key={item.path}
                      value={`recent:${item.path}`}
                      onSelect={() => closeAndNavigate(item.path)}
                    >
                      <ClockCounterClockwise size={16} className="text-text-muted" />
                      <span>{item.label}</span>
                    </CommandItem>
                  ))}
                </CommandGroup>
              )}

              {searchHistory.length > 0 && (
                <>
                  {recentItems.length > 0 && <CommandSeparator />}
                  <CommandGroup heading="Recent Searches">
                    {searchHistory.map((item) => (
                      <CommandItem
                        key={`${item.query}-${item.searchedAt}`}
                        value={`history:${item.query}`}
                        onSelect={() => replaySearch(item.query)}
                      >
                        <MagnifyingGlass size={16} className="text-text-muted" />
                        <span>{item.query}</span>
                      </CommandItem>
                    ))}
                    <CommandItem
                      value="clear-history"
                      onSelect={() => {
                        clearHistory();
                      }}
                      className="text-text-muted"
                    >
                      <X size={16} />
                      <span>Clear search history</span>
                    </CommandItem>
                  </CommandGroup>
                </>
              )}

              {recentItems.length === 0 && searchHistory.length === 0 && (
                <CommandEmpty>
                  Type to search, or use &ldquo;&gt;&rdquo; for commands...
                </CommandEmpty>
              )}
            </>
          )}

          {/* ----------------------------------------------------------------
              SEARCH MODE (no '>' prefix, has query)
          ---------------------------------------------------------------- */}
          {!isCommandMode && !isEmptyQuery && (
            <>
              {searchQuery.length < 2 && (
                <CommandEmpty>
                  Type at least 2 characters to search...
                </CommandEmpty>
              )}
              {searchQuery.length >= 2 && isSearchLoading && (
                <CommandEmpty>Searching...</CommandEmpty>
              )}
              {searchQuery.length >= 2 &&
                !isSearchLoading &&
                !hasSearchResults && (
                  <CommandEmpty>No results found for &ldquo;{searchQuery}&rdquo;</CommandEmpty>
                )}
              {hasSearchResults &&
                Object.entries(groupedResults).map(([type, items]) => (
                  <CommandGroup
                    key={type}
                    heading={TYPE_LABELS[type] ?? type}
                  >
                    {items.slice(0, 5).map((item) => (
                      <CommandItem
                        key={item.id}
                        value={item.id}
                        onSelect={() => selectSearchResult(item)}
                      >
                        {getTypeIcon(item.type)}
                        <span>{item.label}</span>
                      </CommandItem>
                    ))}
                  </CommandGroup>
                ))}
            </>
          )}

          {/* ----------------------------------------------------------------
              COMMAND MODE ('>' prefix) — VS Code style
          ---------------------------------------------------------------- */}
          {isCommandMode && (
            <>
              {filteredCommands.length === 0 && (
                <CommandEmpty>No matching commands</CommandEmpty>
              )}
              {filteredCommands.length > 0 && (
                <>
                  <CommandSeparator />
                  <CommandGroup heading="Navigation">
                    {filteredCommands.map((cmd) => (
                      <CommandItem
                        key={cmd.id}
                        value={cmd.id}
                        onSelect={() => executeCommand(cmd)}
                      >
                        {cmd.icon ?? <ArrowSquareOut size={16} />}
                        <span>{cmd.label}</span>
                        {cmd.shortcut && (
                          <CommandShortcut>{cmd.shortcut}</CommandShortcut>
                        )}
                      </CommandItem>
                    ))}
                  </CommandGroup>
                </>
              )}
            </>
          )}

        </CommandList>
      </Command>
    </CommandDialog>
  );
}
