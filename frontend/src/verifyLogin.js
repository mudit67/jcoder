export function isLoggedIn() {
  const token = localStorage.getItem("accessToken");
  return !!token;
}