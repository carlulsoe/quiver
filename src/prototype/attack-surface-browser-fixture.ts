export function createBrowserFixture(servers: Bun.Server<unknown>[]) {
  const state = {
    graphqlRequests: 0,
    blockedWorkflowRequests: 0,
    blockedVisitOnlyPosts: 0,
    primaryAuthorization: null as string | null,
    primaryApiKey: null as string | null,
    primarySocketAuthorization: null as string | null,
    primaryCookie: null as string | null,
    secondaryAuthorization: null as string | null,
    secondaryApiKey: null as string | null,
    secondaryCookie: null as string | null,
    secondaryStoredValue: null as string | null,
    secondaryVisibleCookie: null as string | null,
    secondarySocketConnections: 0,
    primaryLogoutRequests: 0,
    destructiveWorkflowRequests: 0,
    activeVisitOnlyGets: 0,
    wrongSearchActions: 0,
    searchSubmitterValue: null as string | null,
    primaryOrigin: "",
  };
  const secondary = Bun.serve({
    port: 0,
    websocket: {
      open() {
        state.secondarySocketConnections += 1;
      },
      message() {},
    },
    fetch(request, server) {
      const url = new URL(request.url);
      if (url.pathname === "/socket" && server.upgrade(request)) return;
      if (url.pathname === "/blocked") state.blockedVisitOnlyPosts += 1;
      if (url.pathname === "/active-get") state.activeVisitOnlyGets += 1;
      if (url.pathname === "/passive") {
        state.secondaryStoredValue = url.searchParams.get("stored");
        state.secondaryVisibleCookie = url.searchParams.get("cookie");
      }
      if (url.pathname === "/visitor") {
        state.secondaryAuthorization = request.headers.get("authorization");
        state.secondaryApiKey = request.headers.get("xapikey");
        state.secondaryCookie = request.headers.get("cookie");
        return html(`
          <script>
            new WebSocket('ws://' + location.host + '/socket');
            const pixel = new Image();
            pixel.src = '/passive?stored=' + localStorage.getItem('primary-secret') + '&cookie=' + encodeURIComponent(document.cookie);
            fetch('/blocked', { method: 'POST', body: 'must-not-arrive' }).catch(() => {});
            fetch('${state.primaryOrigin}/logout').catch(() => {});
          </script>
          <form aria-label="Visitor lookup" action="/interact" method="get">
            <input name="query" placeholder="lookup">
            <button type="submit">Continue</button>
          </form>
        `);
      }
      return new Response("ok");
    },
  });
  servers.push(secondary);

  const primary = Bun.serve({
    port: 0,
    websocket: {
      open(socket) {
        socket.send("welcome");
      },
      message(socket, message) {
        socket.send(message);
      },
    },
    async fetch(request, server) {
      const url = new URL(request.url);
      if (url.pathname === "/socket") {
        state.primarySocketAuthorization = request.headers.get("authorization");
        if (server.upgrade(request)) return;
      }
      if (url.pathname === "/") {
        state.primaryAuthorization = request.headers.get("authorization");
        state.primaryApiKey = request.headers.get("xapikey");
        state.primaryCookie = request.headers.get("cookie");
        return html(`
          <script>
            const socket = new WebSocket('ws://' + location.host + '/socket');
            socket.addEventListener('open', () => socket.send('observe-only'));
            new WebSocket('ws://' + location.host + '/socket');
            fetch('http://127.0.0.1:${secondary.port}/active-get').catch(() => {});
          </script>
          <a href="http://127.0.0.1:${secondary.port}/visitor">Documentation</a>
          <form aria-label="Lookup remote documentation" action="http://127.0.0.1:${secondary.port}/interact" method="get">
            <input name="query">
            <button type="submit">Lookup</button>
          </form>
          <form aria-label="Search inventory" action="/wrong-search-action" method="post">
            <input name="query" placeholder="Search term">
            <button type="submit" name="workflow" value="inventory-search" formaction="/step" formmethod="get">Search</button>
          </form>
          <form aria-label="Upload evidence" action="/upload" method="post" enctype="multipart/form-data">
            <input name="description">
            <input name="attachment" type="file">
            <button type="submit">Upload</button>
          </form>
          <form aria-label="Upload alternate evidence" action="/upload" method="post" enctype="multipart/form-data">
            <input name="note">
            <input name="screenshot" type="file">
            <button type="submit">Upload alternate</button>
          </form>
        `);
      }
      if (url.pathname === "/step") {
        state.searchSubmitterValue = url.searchParams.get("workflow");
        return html(`
          <form aria-label="Delete account" action="/delete" method="post">
            <input name="confirm">
            <button type="submit">Delete</button>
          </form>
          <form aria-label="Continue account cancellation" action="/workflow/one" method="post">
            <input name="confirm">
            <button type="submit">Continue</button>
          </form>
          <form aria-label="Verify workspace closure" action="/workflow/two" method="post">
            <input name="confirm">
            <button type="submit">Verify</button>
          </form>
          <form aria-label="Continue profile deactivation" action="/workflow/three" method="post">
            <input name="confirm">
            <button type="submit">Continue</button>
          </form>
          <form aria-label="Verify subscription termination" action="/workflow/four" method="post">
            <input name="confirm">
            <button type="submit">Verify</button>
          </form>
          <form aria-label="Continue account deletion" action="/workflow/five" method="post">
            <input name="confirm">
            <button type="submit">Continue</button>
          </form>
          <form aria-label="Verify service suspension" action="/workflow/six" method="post">
            <input name="confirm">
            <button type="submit">Verify</button>
          </form>
          <form aria-label="Continue data archival" action="/workflow/seven" method="post">
            <input name="confirm">
            <button type="submit">Continue</button>
          </form>
          <form action="/logout" method="get">
            <input name="confirm">
            <button type="submit">Submit</button>
          </form>
          <form aria-label="Verify blocked workflow" action="/blocked-workflow" method="post">
            <input name="code">
            <button type="submit">Verify</button>
          </form>
          <form aria-label="Continue GraphQL workflow" action="/graphql" method="post">
            <textarea name="query">mutation SaveItem { saveItem(input: { name: "sample" }) { id } }</textarea>
            <button type="submit">Continue</button>
          </form>
        `);
      }
      if (url.pathname === "/graphql") {
        if (request.method === "POST") state.graphqlRequests += 1;
        return Response.json({ data: { saveItem: { id: "1" } } });
      }
      if (url.pathname === "/blocked-workflow") state.blockedWorkflowRequests += 1;
      if (url.pathname === "/wrong-search-action") state.wrongSearchActions += 1;
      if (url.pathname === "/logout") state.primaryLogoutRequests += 1;
      if (
        [
          "/workflow/one",
          "/workflow/two",
          "/workflow/three",
          "/workflow/four",
          "/workflow/five",
          "/workflow/six",
          "/workflow/seven",
        ].includes(url.pathname)
      )
        state.destructiveWorkflowRequests += 1;
      return new Response("ok");
    },
  });
  servers.push(primary);
  return { primary, secondary, state };
}

function html(body: string): Response {
  return new Response(`<!doctype html><html><body>${body}</body></html>`, {
    headers: { "content-type": "text/html" },
  });
}
