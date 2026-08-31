const DYNAMIC_PATH_SEGMENT =
  /^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|<[^>]+>|\{[^}]+\})$/i;

export function normalizeEndpoint(endpoint: string): string {
  const url = new URL(endpoint, "http://scope.invalid");
  const path = url.pathname
    .split("/")
    .map((encodedSegment) => {
      const segment = decodeURIComponent(encodedSegment);
      return DYNAMIC_PATH_SEGMENT.test(segment) ? "{id}" : segment;
    })
    .join("/");

  return path === "/" ? path : path.replace(/\/+$/, "");
}
