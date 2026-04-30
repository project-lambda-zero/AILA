import { authorizedRequestJson } from "@platform/api/http";

export interface HelloWorldStatus {
  module: string;
  status: string;
}

export async function fetchHelloWorldStatus(): Promise<HelloWorldStatus> {
  return authorizedRequestJson<HelloWorldStatus>("/hello_world/status");
}
