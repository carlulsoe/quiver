import { describe, expect, it } from "vitest";
import { RouteDiscovery } from "./route-discovery.ts";

const origin = "http://127.0.0.1:8888";

function analyzeJavaScript(source: string): RouteDiscovery {
  const discovery = new RouteDiscovery(origin);
  discovery.analyzeDocument({
    path: "/app.js",
    source,
    contentType: "application/javascript",
  });
  return discovery;
}

describe("route discovery", () => {
  it("extracts only same-origin crawlable documents from HTML", () => {
    const discovery = new RouteDiscovery(origin);
    const found = discovery.analyzeDocument({
      path: "/",
      source:
        '<a href="/docs">Docs</a><script src="/assets/app.js"></script><a href="https://example.com/escape">elsewhere</a>',
      contentType: "text/html",
    });

    expect(found.routes).toEqual(["/docs", "/assets/app.js"]);
    expect(found.crawlableLinks).toEqual(["/docs", "/assets/app.js"]);
  });

  it("derives routes from JavaScript string composition", () => {
    const discovery = analyzeJavaScript(
      'const service="identity/",routes={LOGIN:"api/auth/login",DASHBOARD:"api/v2/user/dashboard"};fetch(service+routes.LOGIN);fetch(service+routes.DASHBOARD)',
    );

    expect(discovery.routeDetails().map(({ path }) => path)).toEqual([
      "/identity/api/auth/login",
      "/identity/api/v2/user/dashboard",
    ]);
  });

  it("records GET call sites and authentication hints", () => {
    const discovery = analyzeJavaScript(
      'fetch("/api/accounts", { method: "GET", headers: { Authorization: `Bearer ${token}` } })',
    );

    expect(discovery.routeDetails()).toContainEqual({
      path: "/api/accounts",
      sources: ["/app.js"],
      getCallSites: [{ documentPath: "/app.js", authentication: "likely" }],
      identifierSources: [],
    });
  });

  it("resolves route aliases and named authentication headers", () => {
    const discovery = analyzeJavaScript(
      'const service="identity/", routes={USERS:"api/v2/users"}; const headers={Authorization:`Bearer ${token}`}; const endpoint=service+routes.USERS; fetch(endpoint,{headers,method:"GET"})',
    );

    expect(discovery.routeDetails()).toContainEqual({
      path: "/identity/api/v2/users",
      sources: ["/app.js"],
      getCallSites: [{ documentPath: "/app.js", authentication: "likely" }],
      identifierSources: [],
    });
  });

  it("links dynamic identifiers to the GET collection that can supply them", () => {
    const discovery = analyzeJavaScript(
      'fetch("/api/accounts",{method:"GET"}); fetch(`/api/accounts/${accountId}/transactions`,{method:"GET"})',
    );

    expect(discovery.routeDetails()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: "/api/accounts/{accountId}/transactions",
          identifierSources: [{ parameter: "accountId", sourcePath: "/api/accounts" }],
        }),
      ]),
    );
  });

  it("bounds cyclic alias resolution", () => {
    const discovery = analyzeJavaScript('const endpoint=endpoint; fetch(endpoint,{method:"GET"})');

    expect(discovery.routeDetails()).toEqual([]);
  });

  it("omits unresolved first-segment templates from actionable route intelligence", () => {
    const discovery = analyzeJavaScript(
      "fetch(`/${theme}/${version}/styles.json`,{method:'GET'}); fetch('/api/accounts',{method:'GET'})",
    );

    expect(discovery.routeDetails().map(({ path }) => path)).toEqual(["/api/accounts"]);
  });
});
