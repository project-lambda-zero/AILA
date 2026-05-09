import { useNavigate } from "react-router";
import { Palette, SignOut, User, Sun, Moon } from "@phosphor-icons/react";

import { useAuthStore } from "@platform/auth/useAuthStore";
import { useTheme } from "@/providers/ThemeProvider";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

function getUserInitials(username: string | null | undefined): string {
  if (!username) return "?";
  return username.charAt(0).toUpperCase();
}

const THEME_LABELS: Record<string, string> = {
  "frutiger-aero": "Frutiger Aero",
  synthwave: "Synthwave",
  vaporwave: "Vaporwave",
  ps1: "PlayStation 1",
  ps2: "PlayStation 2",
  "cyberpunk-2077": "Cyberpunk 2077",
  matrix: "The Matrix",
  "truman-show": "Truman Show",
  "half-life-1": "Half-Life 1",
  "y2k-fever": "Y2K Fever",
  vendetta: "Vendetta",
};

export function UserAvatarMenu() {
  const { username, role, logout } = useAuthStore();
  const { theme, mode, cycleTheme, toggleMode, isDark } = useTheme();
  const navigate = useNavigate();

  function handleSignOut() {
    logout();
    navigate("/login");
  }

  function handleSettings() {
    navigate("/settings");
  }

  const initials = getUserInitials(username);

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <button
            type="button"
            className="flex items-center rounded-full focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2"
            aria-label="User menu"
          />
        }
      >
        <Avatar size="sm" className="cursor-pointer border-2 border-accent/30 hover:border-accent transition-colors">
          <AvatarFallback className="bg-accent/20 text-accent font-mono font-bold text-xs">
            {initials}
          </AvatarFallback>
        </Avatar>
      </DropdownMenuTrigger>

      <DropdownMenuContent align="end" side="bottom" sideOffset={8}>
        <DropdownMenuLabel className="flex flex-col gap-1 pb-2">
          <span className="font-medium text-sm text-foreground">
            {username ?? "Unknown"}
          </span>
          <Badge variant="outline" className="w-fit text-xs capitalize">
            {role ?? "\u2014"}
          </Badge>
        </DropdownMenuLabel>

        <DropdownMenuSeparator />

        <DropdownMenuItem onClick={handleSettings} className="gap-2 cursor-pointer">
          <User size={14} />
          Profile &amp; Settings
        </DropdownMenuItem>

        <DropdownMenuItem onClick={cycleTheme} className="gap-2 cursor-pointer">
          <Palette size={14} />
          {THEME_LABELS[theme] ?? theme}
        </DropdownMenuItem>

        <DropdownMenuItem onClick={toggleMode} className="gap-2 cursor-pointer">
          {isDark ? <Sun size={14} /> : <Moon size={14} />}
          {isDark ? "Light mode" : "Dark mode"}
        </DropdownMenuItem>

        <DropdownMenuSeparator />

        <DropdownMenuItem
          onClick={handleSignOut}
          className="gap-2 cursor-pointer text-destructive focus:text-destructive"
        >
          <SignOut size={14} />
          Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
