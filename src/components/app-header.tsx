import React from "react";
import { SidebarTrigger } from "./ui/sidebar";
import { Separator } from "./ui/separator";
import Link from "next/link";
import { ArrowLeft, ChevronDown, LogOut, Settings, User2 } from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "./ui/dropdown-menu";
import { Button } from "./ui/button";

export default function AppHeader() {
  const session = {
    user: {
      email: "",
    },
  };
  return (
    <header className="flex h-16 shrink-0 items-center gap-2 border-b bg-white px-4">
      <SidebarTrigger className="-ml-1" />
      <Separator orientation="vertical" className="mr-2 h-4" />

      {/* Account Dropdown */}
      <div className="ml-auto">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" className="flex items-center gap-2">
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-blue-600 text-white text-sm">
                {"JD"}
              </div>
              <div className="hidden md:block text-left">
                <p className="text-sm font-medium">{"john doe"}</p>
                <p className="text-xs text-muted-foreground">{"HR"}</p>
              </div>
              <ChevronDown className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuLabel>My Account</DropdownMenuLabel>
            <DropdownMenuSeparator />

            {/* Header Login Info */}
            {session?.user?.email ? (
              <DropdownMenuItem>
                <span className="flex items-center gap-1">
                  <LogOut /> Sign Out
                </span>
              </DropdownMenuItem>
            ) : (
              <DropdownMenuItem>
                <Link href="/login" className="w-full cursor-pointer">
                  {/* <LogIn className="mr-2 h-4 w-4" /> */}
                  Login
                </Link>
              </DropdownMenuItem>
            )}
            {/* <DropdownMenuSeparator /> */}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
