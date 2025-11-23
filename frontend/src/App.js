import React from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
  Link,
  useNavigate,
} from "react-router-dom";
import SignUp from "./SignUp";
import Login from "./Login";
import Dashboard from "./Dashboard";
import { isLoggedIn } from "./verifyLogin";
function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(";").shift();
  return null;
}
function Brand() {
  return (
    <div className="top-row">
      <div>
        <div style={{ fontSize: 18, fontWeight: 700 }}>AuthLab</div>
        <div style={{ fontSize: 11, color: "#9ca3af" }}>Minimal JWT</div>
      </div>
      <div className="badge">Demo</div>
    </div>
  );
}

export default function App() {
  return (
    <Router>
      <Routes>
        <Route
          path="/"
          element={
            getCookie("accessToken") ? (
              <Navigate to="/dashboard" replace />
            ) : (
              <Navigate to="/login" replace />
            )
          }
        />
        <Route
          path="/signup"
          element={
            getCookie("accessToken") ? (
              <Navigate to="/dashboard" replace />
            ) : (
              <div className="auth-root">
                <div className="auth-card">
                  <Brand />
                  <SignUp />
                  <div className="link-row">
                    Already have an account?{" "}
                    <Link to="/login" className="link">
                      Log in
                    </Link>
                  </div>
                </div>
              </div>
            )
          }
        />
        <Route
          path="/login"
          element={
            <div className="auth-root">
              <div className="auth-card">
                <Brand />
                <Login />
                <div className="link-row">
                  New here?{" "}
                  <Link to="/signup" className="link">
                    Create an account
                  </Link>
                </div>
              </div>
            </div>
          }
        />
        <Route
          path="/dashboard"
          element={
            // getCookie("accessToken") ? (
            <div className="auth-root">
              <Dashboard />
            </div>
            // ) : 
            //  <Navigate to="/login" replace />
          }
        />
  
        <Route path="*" element={<Navigate to="/signup" replace />} />
      </Routes>
    </Router>
  );
}
