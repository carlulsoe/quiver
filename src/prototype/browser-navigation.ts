export function isExpectedDocumentNavigation(
  isNavigationRequest: boolean,
  isMainFrame: boolean,
  url: URL,
  expected: URL,
): boolean {
  return (
    !isNavigationRequest ||
    (isMainFrame &&
      url.origin === expected.origin &&
      `${url.pathname}${url.search}` === `${expected.pathname}${expected.search}`)
  );
}

export function isCompletedTransition(status: number): boolean {
  return status >= 200 && status < 400;
}
