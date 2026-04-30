import { lazy } from "react";
import type { ModuleFrontendSpec } from "@platform/extension-registry/types";

const HelloWorldPage = lazy(() => import("./HelloWorldPage"));

export const frontendSpec = {
  moduleId: "hello_world",
  nav: [
    {
      id: "hello_world.home",
      slot: "sidebar.main" as const,
      label: "Hello World",
      to: "/hello_world",
      order: 900,
      description: "Example module",
    },
  ],
  routes: [
    {
      id: "hello_world.home",
      path: "/hello_world",
      title: "Hello World",
      nav: true,
      slot: "page.full" as const,
      page: HelloWorldPage,
      breadcrumb: "Hello World",
    },
  ],
} satisfies ModuleFrontendSpec;
