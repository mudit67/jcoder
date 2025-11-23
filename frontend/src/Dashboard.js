import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";

function getCookie(name) {
  if (typeof document === "undefined") return null;
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(";").shift();
  return null;
}

function setCookie(name, value, days = 30) {
  const expires = new Date();
  expires.setTime(expires.getTime() + (days * 24 * 60 * 60 * 1000));
  document.cookie = `${name}=${value}; expires=${expires.toUTCString()}; path=/; SameSite=Strict; Secure=${window.location.protocol === 'https:'}`;
}

function deleteCookie(name) {
  document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
}

function checkRefreshTokenExists() {
  const refreshToken = getCookie("refreshToken");
  return !!refreshToken;
}

function base64UrlDecode(str) {
  try {
    let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
    const pad = base64.length % 4;
    if (pad === 2) base64 += "==";
    else if (pad === 3) base64 += "=";
    else if (pad === 1) base64 += "===";

    return atob(base64);
  } catch (e) {
    return null;
  }
}

function getTimeUntilExpiration(expiresAt) {
  if (!expiresAt) return null;
  
  const now = new Date();
  const expiry = new Date(expiresAt);
  const diffMs = expiry.getTime() - now.getTime();
  
  if (diffMs <= 0) {
    return "Expired";
  }
  
  const diffSeconds = Math.floor(diffMs / 1000);
  const diffMinutes = Math.floor(diffSeconds / 60);
  const diffHours = Math.floor(diffMinutes / 60);
  const diffDays = Math.floor(diffHours / 24);
  
  if (diffDays > 0) {
    return `${diffDays}d ${diffHours % 24}h ${diffMinutes % 60}m`;
  } else if (diffHours > 0) {
    return `${diffHours}h ${diffMinutes % 60}m ${diffSeconds % 60}s`;
  } else if (diffMinutes > 0) {
    return `${diffMinutes}m ${diffSeconds % 60}s`;
  } else {
    return `${diffSeconds}s`;
  }
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [token, setToken] = useState(
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMjM0NSIsIm5hbWUiOiJUZXN0IFVzZXIiLCJpYXQiOjE2OTk5OTk5OTl9.tf7WAe8ItNjqEea3Fsw5yJAkw1G8NxYn0G-4Av44CjE"
  );
  const [isLoading, setIsLoading] = useState(false);
  const [username, setUsername] = useState("");
  const [issuedAt, setIssuedAt] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [expiresAtRaw, setExpiresAtRaw] = useState(""); // Store raw timestamp for calculations
  const [secretMessage, setSecretMessage] = useState("");
  const [hasRefreshToken, setHasRefreshToken] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [isRetrying, setIsRetrying] = useState(false);
  const [showLoginPrompt, setShowLoginPrompt] = useState(false);
  const [currentTime, setCurrentTime] = useState(new Date());
  useEffect(() => {
    let data = localStorage.getItem("data");
    if (data) {
      let result = JSON.parse(data)
      setUsername(result.username);
      setIssuedAt(new Date(result.issuedAt).toLocaleString());
      if (result.expiresAt) {
        setExpiresAt(new Date(result.expiresAt).toLocaleString());
        setExpiresAtRaw(result.expiresAt); // Store raw timestamp
      }
    }
    let token = localStorage.getItem("accessToken");
    if (token) {
      setToken(token);
      // Load secret message on mount
      loadSecretMessage(token);
    }
    let refreshToken = getCookie("refreshToken");
    setHasRefreshToken(!!refreshToken);
    
    // Update current time every second for live countdown
    const timer = setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);
    
    return () => clearInterval(timer);
  }, []);
  let header = null;
  let payload = null;
  let signature = null;
  let algo = null;

  if (token) {
    const parts = token.split(".");
    if (parts.length === 3) {
      const [h, p, s] = parts;
      signature = s;
      try {
        const hJson = base64UrlDecode(h);
        const pJson = base64UrlDecode(p);
        header = hJson ? JSON.parse(hJson) : null;
        payload = pJson ? JSON.parse(pJson) : null;
        algo = header?.alg || null;
      } catch (e) {
        console.log(e);
      }
    }
  }

  const handleBackToLogin = () => navigate("/login");

  const logout = () => {
    localStorage.removeItem("accessToken");
    deleteCookie("refreshToken");
    setHasRefreshToken(false); // Update state when refresh token is removed
    localStorage.removeItem("data");
    navigate("/login", { replace: true });
  };

  const loadSecretMessage = async (accessToken) => {
    setIsLoading(true);
    setError(""); // Clear previous errors
    try {
      const res = await fetch("http://localhost:3000/api/user/secret", {
        method: "GET",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
      });

      if (res.status === 401) {
        // Check current refresh token status immediately on 401
        const currentlyHasRefreshToken = checkRefreshTokenExists();
        setHasRefreshToken(currentlyHasRefreshToken);
        
        const errorData = await res.json().catch(() => ({}));
        const errorMessage = errorData.error || "Token expired";
        
        if (currentlyHasRefreshToken && !isRetrying) {
          // Token expired but refresh token available, attempt refresh
          setError(errorMessage);
          setIsRetrying(true);
          setTimeout(async () => {
            try {
              const newToken = await handleTokenRefresh();
              if (newToken) {
                // Retry with new token
                setIsRetrying(false);
                return loadSecretMessage(newToken);
              } else {
                setError("Failed to refresh token. Please login again.");
                setIsRetrying(false);
              }
            } catch (refreshError) {
              setError("Failed to refresh token. Please login again.");
              setIsRetrying(false);
            }
          }, 2000);
          return;
        } else {
          // No refresh token available
          setError(`${errorMessage}. No refresh token available - please login again.`);
          setTimeout(() => {
            setShowLoginPrompt(true);
          }, 2000);
          return;
        }
      }

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        const errorMessage = errorData.error || `Request failed with status ${res.status}`;
        throw new Error(errorMessage);
      }

      const result = await res.json();
      if (result?.data?.secretMessage) {
        setSecretMessage(result.data.secretMessage);
        setError(""); // Clear any previous errors on success
      }
    } catch (error) {
      console.error("Error fetching secret message:", error);
      setError(error.message);
      
      // If refresh failed and we're out of options, suggest login
      if (error.message.includes("refresh") || error.message.includes("login")) {
        setTimeout(() => {
          setShowLoginPrompt(true);
        }, 1000);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleTokenRefresh = async () => {
    const refreshToken = getCookie("refreshToken");
    const data = JSON.parse(localStorage.getItem("data") || "{}");
    const originalExpiresIn = data.originalExpiresIn;
    
    if (!refreshToken) return null;

    setIsRefreshing(true);
    try {
      const res = await fetch("http://localhost:3000/api/auth/refresh", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ 
          refreshToken,
          originalExpiresIn 
        }),
      });

      if (!res.ok) throw new Error("Failed to refresh token");

      const result = await res.json();
      if (result?.data?.accessToken) {
        setToken(result.data.accessToken);
        localStorage.setItem("accessToken", result.data.accessToken);
        setCookie("refreshToken", result.data.refreshToken, 30);
        setHasRefreshToken(true); // Update state when refresh token is set
        
        // Update stored data with new timestamps but preserve originalExpiresIn
        data.issuedAt = result.data.issuedAt;
        data.expiresAt = result.data.expiresAt;
        localStorage.setItem("data", JSON.stringify(data));
        
        setIssuedAt(new Date(result.data.issuedAt).toLocaleString());
        setExpiresAt(new Date(result.data.expiresAt).toLocaleString());
        setExpiresAtRaw(result.data.expiresAt); // Store raw timestamp
        
        return result.data.accessToken;
      }
      return null;
    } catch (error) {
      console.error("Error refreshing token:", error);
      // If refresh fails, the refresh token might be invalid, update state
      setHasRefreshToken(checkRefreshTokenExists());
      return null;
    } finally {
      setIsRefreshing(false);
    }
  };

  return (
    <div className="dashboard-card">
      <div className="dashboard-header">
        <div>
          <div className="auth-title">JWT Dashboard</div>
          <div className="auth-subtitle" onClick={logout}>
            Logout
          </div>
        </div>
        <div className="pill">
          {algo ? `Algorithm: ${algo}` : "No token loaded"}
        </div>
      </div>

      {token && (
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-start",
            width: "100%",
            marginBottom: 12,
            gap: "16px",
          }}
        >
          <div style={{ flex: "1" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
              <div className="code-title">Secret Message</div>
              <button
                onClick={() => loadSecretMessage(token)}
                disabled={isLoading || isRetrying}
                style={{
                  padding: "4px 8px",
                  fontSize: "12px",
                  borderRadius: "4px",
                  border: "1px solid #555",
                  background: (isLoading || isRetrying) ? "rgba(24, 69, 166, 0.1)" : "rgba(24, 69, 166, 0.15)",
                  color: (isLoading || isRetrying) ? "#64748b" : "#cbd5e1",
                  cursor: (isLoading || isRetrying) ? "not-allowed" : "pointer",
                  transition: "all 0.2s ease-in-out",
                  opacity: (isLoading || isRetrying) ? 0.5 : 1
                }}
                onMouseEnter={(e) => {
                  if (!isLoading && !isRetrying) {
                    e.target.style.background = "rgba(24, 69, 166, 0.25)";
                  }
                }}
                onMouseLeave={(e) => {
                  if (!isLoading && !isRetrying) {
                    e.target.style.background = "rgba(24, 69, 166, 0.15)";
                  }
                }}
              >
                {(isLoading || isRetrying) ? "⟳" : "🔄 Reload"}
              </button>
            </div>
            <div className="code-block" style={{ marginTop: 6, minHeight: "40px", display: "flex", alignItems: "center" }}>
              {isLoading || isRetrying ? (
                <div style={{ display: "flex", alignItems: "center", gap: "8px", width: "100%" }}>
                  <div className="loading-spinner" style={{ margin: "0" }} />
                  <span style={{ fontSize: "14px", opacity: 0.7 }}>
                    {isRetrying ? "Refreshing token and retrying..." : "Loading secret message..."}
                  </span>
                </div>
              ) : error ? (
                <div style={{ color: "#ef4444", fontSize: "14px", padding: "8px" }}>
                  ❌ {error}
                </div>
              ) : secretMessage ? (
                secretMessage
              ) : (
                "No secret message available"
              )}
            </div>
            {(isRefreshing || isRetrying) && (
              <div className="small-label" style={{ marginTop: 4, color: "#f59e0b" }}>
                {isRetrying ? 
                  "⏳ Token expired, waiting to refresh..." : 
                  "🔄 Refreshing access token..."
                }
              </div>
            )}
          </div>

          <div className="token-info" style={{ minWidth: "200px" }}>
            <div className="small-label" style={{ fontWeight: "500" }}>
              {username || "Unknown User"}
            </div>
            <div className="small-label" style={{ fontSize: "12px", opacity: 0.7 }}>
              {issuedAt ? `Issued: ${issuedAt}` : "IssuedAt not available"}
            </div>
            <div className="small-label" style={{ fontSize: "12px", opacity: 0.7 }}>
              {expiresAt ? `Expires: ${expiresAt}` : "ExpiresAt not available"}
            </div>
            {expiresAtRaw && (
              <div className="small-label" style={{ 
                fontSize: "12px", 
                opacity: 0.8, 
                color: getTimeUntilExpiration(expiresAtRaw) === "Expired" ? "#ef4444" : "#fbbf24",
                fontWeight: "500"
              }}>
                {getTimeUntilExpiration(expiresAtRaw) === "Expired" ? 
                  "🔴 Expired" : 
                  `⏰ Expires in ${getTimeUntilExpiration(expiresAtRaw)}`
                }
              </div>
            )}
            {hasRefreshToken ? (
              <div className="small-label" style={{ fontSize: "12px", opacity: 0.7, color: "#059669" }}>
                ✓ Refresh token available
              </div>
            ) : (
              <div className="small-label" style={{ fontSize: "12px", opacity: 0.7, color: "#ef4444" }}>
                ⚠️ No refresh token - relogin required when token expires
              </div>
            )}
          </div>
        </div>
      )}


      {isLoading && (
        <div className="loading-spinner" style={{ marginBottom: 12 }} />
      )}

      {!token && (
        <div>
          <div className="error-text" style={{ marginBottom: 12 }}>
            No <code>accessToken</code> cookie found.
          </div>
          <button className="primary-btn" onClick={handleBackToLogin}>
            Go to Login
          </button>
        </div>
      )}

      {token && !isLoading && (
        <>
          <div className="small-label">Raw token</div>
          <div className="code-block" style={{ marginTop: 6 }}>
            {token}
          </div>

          <div className="columns">
            <div>
              <div className="code-title">Header</div>
              <div className="code-block">
                {header ? (
                  <pre>{JSON.stringify(header, null, 2)}</pre>
                ) : (
                  "Unable to decode header"
                )}
              </div>
            </div>
            <div>
              <div className="code-title">Payload</div>
              <div className="code-block">
                {payload ? (
                  <pre>{JSON.stringify(payload, null, 2)}</pre>
                ) : (
                  "Unable to decode payload"
                )}
              </div>
            </div>
          </div>

          <div style={{ marginTop: 16 }}>
            <div className="code-title">Signature (base64url)</div>
            <div className="code-block">
              {signature || "No signature part found"}
            </div>
          </div>
        </>
      )}

      {showLoginPrompt && (
        <div style={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: "rgba(0, 0, 0, 0.5)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          zIndex: 1000
        }}>
          <div style={{
            backgroundColor: "#1a1a1a",
            padding: "24px",
            borderRadius: "8px",
            border: "1px solid #555",
            maxWidth: "400px",
            textAlign: "center"
          }}>
            <div style={{ marginBottom: "16px", fontSize: "16px", fontWeight: "500" }}>
              Session Expired
            </div>
            <div style={{ marginBottom: "24px", fontSize: "14px", opacity: 0.7 }}>
              {hasRefreshToken ? 
                "Your session has expired. Would you like to go back to login?" :
                "Your session has expired and no refresh token is available. Please login again to continue."
              }
            </div>
            <div style={{ display: "flex", gap: "12px", justifyContent: "center" }}>
              {hasRefreshToken && (
                <button 
                  onClick={() => setShowLoginPrompt(false)}
                  style={{
                    padding: "8px 16px",
                    borderRadius: "4px",
                    border: "1px solid #555",
                    background: "rgba(24, 69, 166, 0.15)",
                    color: "#cbd5e1",
                    cursor: "pointer"
                  }}
                >
                  Cancel
                </button>
              )}
              <button 
                onClick={() => {
                  setShowLoginPrompt(false);
                  logout();
                }}
                className="primary-btn"
                style={{ padding: "8px 16px" }}
              >
                Go to Login
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
