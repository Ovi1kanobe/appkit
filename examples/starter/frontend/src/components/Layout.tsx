import { cn } from "cn"
import type { LucideIcon } from "lucide-react"
import { LogOut } from "lucide-react"
import type { ComponentProps, ReactNode } from "react"
import { NavLink, useLocation } from "react-router"
import { ThemeToggle } from "@/components/ThemeToggle"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSkeleton,
  SidebarProvider,
  SidebarTrigger,
  useSidebar,
} from "@/components/ui/sidebar"
import { Skeleton } from "@/components/ui/skeleton"
import { TooltipProvider } from "@/components/ui/tooltip"
import { refreshSession, useSession } from "@/lib/session"

// The app's name, shown in the sidebar and on the signed-out card.
const title = "Starter"

// Each section's page adds its link here, with its icon and the permission it needs.
const links: { to: string; label: string; icon: LucideIcon; permission?: string }[] = []

export function Layout({ children }: { children: ReactNode }) {
  const session = useSession()
  const location = useLocation()

  if (session.status === "signed-out") {
    return (
      <main className="flex min-h-svh items-center justify-center bg-background p-4 text-foreground">
        <Card className="w-full max-w-sm animate-in duration-200 ease-out fade-in">
          <CardHeader>
            <CardTitle>{title}</CardTitle>
            <CardDescription>You are signed out.</CardDescription>
          </CardHeader>
          <CardContent>
            <Button asChild className="w-full">
              <a href={`/auth/login?next=${encodeURIComponent(location.pathname)}`}>Sign in with Rauthy</a>
            </Button>
          </CardContent>
        </Card>
      </main>
    )
  }

  return (
    <TooltipProvider>
      {/* shadcn's sidebar saves its open state in a cookie; reading it back keeps a collapsed sidebar collapsed after a reload. */}
      <SidebarProvider defaultOpen={!document.cookie.includes("sidebar_state=false")}>
        <Sidebar collapsible="icon">
          <SidebarHeader>
            <SidebarMenu>
              <SidebarMenuItem>
                <SidebarMenuButton asChild size="lg" tooltip={title}>
                  <SidebarLink to="/">
                    <span
                      aria-hidden
                      className="flex size-8 shrink-0 items-center justify-center rounded-md bg-primary font-heading font-semibold text-primary-foreground"
                    >
                      {title[0]}
                    </span>
                    <span className="truncate font-heading font-semibold">{title}</span>
                  </SidebarLink>
                </SidebarMenuButton>
              </SidebarMenuItem>
            </SidebarMenu>
          </SidebarHeader>
          <SidebarContent>
            <SidebarGroup>
              <SidebarGroupContent>
                <SidebarMenu>
                  {session.status === "loading" &&
                    [0, 1, 2].map((row) => (
                      <SidebarMenuItem key={row}>
                        <SidebarMenuSkeleton showIcon />
                      </SidebarMenuItem>
                    ))}
                  {session.status === "signed-in" &&
                    links
                      .filter((link) => !link.permission || session.permissions.includes(link.permission))
                      .map((link) => (
                        <SidebarMenuItem key={link.to}>
                          <SidebarMenuButton
                            asChild
                            tooltip={link.label}
                            isActive={
                              link.to === "/" ? location.pathname === "/" : location.pathname.startsWith(link.to)
                            }
                          >
                            <SidebarLink to={link.to}>
                              <link.icon />
                              <span>{link.label}</span>
                            </SidebarLink>
                          </SidebarMenuButton>
                        </SidebarMenuItem>
                      ))}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          </SidebarContent>
          <SidebarFooter>
            <SidebarMenu>
              <SidebarMenuItem>
                {session.status === "signed-in" ? (
                  <form method="post" action="/auth/logout">
                    <SidebarMenuButton
                      type="submit"
                      tooltip="Sign out"
                      aria-label={`Sign out ${session.user.email ?? session.user.subject}`}
                    >
                      <LogOut />
                      <span className="truncate">{session.user.email ?? session.user.subject}</span>
                    </SidebarMenuButton>
                  </form>
                ) : (
                  <SidebarMenuSkeleton showIcon />
                )}
              </SidebarMenuItem>
            </SidebarMenu>
          </SidebarFooter>
        </Sidebar>
        <SidebarInset>
          {/* As tall as the sidebar's title row, expanded or collapsed, so the trigger lines up with the title. */}
          <header className="flex h-16 shrink-0 items-center gap-2 border-b px-4 transition-[height] duration-200 ease-out group-has-data-[collapsible=icon]/sidebar-wrapper:h-12">
            <SidebarTrigger className="-ml-1" />
            <div className="ml-auto flex items-center gap-2">
              <ThemeToggle />
            </div>
          </header>
          <div className="mx-auto w-full max-w-3xl px-4 py-8">
            {session.status === "loading" && <PageSkeleton />}
            {session.status === "unavailable" && <ServerUnreachable />}
            {session.status === "signed-in" && children}
          </div>
          {session.status === "signed-in" && session.refreshFailed && (
            <ServerUnreachable className="fixed inset-x-4 bottom-4 z-50 mx-auto max-w-md shadow-sm" />
          )}
        </SidebarInset>
      </SidebarProvider>
    </TooltipProvider>
  )
}

// A sidebar link. On phones the sidebar is a sheet over the page, so opening a link closes it.
function SidebarLink({ onClick, ...props }: ComponentProps<typeof NavLink>) {
  const { setOpenMobile } = useSidebar()
  return (
    <NavLink
      end
      {...props}
      onClick={(event) => {
        onClick?.(event)
        setOpenMobile(false)
      }}
    />
  )
}

// Shown in place of the page when the first session load fails, and over the page
// when a later refresh fails, so a signed-in page stays readable.
function ServerUnreachable({ className }: { className?: string }) {
  return (
    <div
      role="status"
      className={cn(
        "flex animate-in items-center justify-between gap-3 rounded-lg border bg-card px-4 py-3 text-sm duration-200 ease-out fade-in",
        className,
      )}
    >
      <p className="text-destructive">The server cannot be reached.</p>
      <Button variant="outline" size="sm" onClick={() => void refreshSession()}>
        Retry
      </Button>
    </div>
  )
}

// A page card with a title, a description, and a few rows, the shape every page starts with.
function PageSkeleton() {
  return (
    <Card>
      <CardHeader>
        <div className="flex h-[1.375rem] items-center">
          <Skeleton className="h-4 w-32" />
        </div>
        <div className="flex h-5 items-center">
          <Skeleton className="h-3.5 w-64 max-w-full" />
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <Skeleton className="h-8 w-full" />
        <Skeleton className="h-5 w-3/4" />
        <Skeleton className="h-5 w-1/2" />
      </CardContent>
    </Card>
  )
}
