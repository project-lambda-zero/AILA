import { useNavigate } from "react-router";
import { SignOut } from "@phosphor-icons/react/dist/csr/SignOut";
import { User } from "@phosphor-icons/react/dist/csr/User";

import { useAuthStore } from "@platform/auth/useAuthStore";
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

export function UserAvatarMenu() {
  const { username, role, logout } = useAuthStore();
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
            className="touch-target flex items-center rounded-full focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2"
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
