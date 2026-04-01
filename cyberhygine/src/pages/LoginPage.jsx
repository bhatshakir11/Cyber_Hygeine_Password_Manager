import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import AnimatedBackground from "../components/AnimatedBackground";
import apiClient from "../apiClient";
import API_BASE_URL from "../config";
import { loginWithFingerprint, registerFingerprint, supportsWebAuthn } from "../utils/webauthn";

const LoginPage = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [fingerprintLoading, setFingerprintLoading] = useState(false);
  const navigate = useNavigate();

  const maybePromptFingerprintRegistration = async () => {
    if (!supportsWebAuthn()) return;
    try {
      const statusRes = await apiClient.get("/fingerprints/status");
      if (statusRes.data?.has_fingerprint) return;
      const consent = window.confirm(
        "Would you like to register fingerprint/Windows Hello login now?"
      );
      if (!consent) return;
      await registerFingerprint();
      alert("Fingerprint login is enabled.");
    } catch (err) {
      console.error(err);
      alert("Logged in, but fingerprint registration failed. You can try again after login.");
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setError("");
    try {
      const res = await axios.post(`${API_BASE_URL}/login`, { username, password });
      if (res.data.success) {
        localStorage.setItem("token", res.data.token);
        localStorage.removeItem("user_id");
        navigate("/dashboard");
        window.setTimeout(() => {
          maybePromptFingerprintRegistration();
        }, 0);
      } else {
        setError(res.data.message || "Invalid credentials");
      }
    } catch (err) {
      setError("Login failed. Please try again.");
    }
  };

  const handleFingerprintLogin = async () => {
    setError("");
    if (!supportsWebAuthn()) {
      setError("Fingerprint login is not supported in this browser.");
      return;
    }
    setFingerprintLoading(true);
    try {
      const res = await loginWithFingerprint();
      if (res.success) {
        localStorage.setItem("token", res.token);
        localStorage.removeItem("user_id");
        navigate("/dashboard");
      } else {
        setError(res.message || "Fingerprint login failed.");
      }
    } catch (err) {
      setError("Fingerprint login failed. Try password login first.");
    } finally {
      setFingerprintLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-900 via-blue-900 to-purple-900">
      <AnimatedBackground />
      <div className="glass-card rounded-2xl shadow-2xl p-8 w-full max-w-md relative z-10 animate-fade-in">
        <h2 className="text-4xl font-bold text-center bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent mb-8">Sign In</h2>
        <form onSubmit={handleLogin}>
          <div className="mb-4">
            <label className="block text-cyan-300 font-semibold mb-2">Username</label>
            <input
              type="text"
              className="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/20 text-white focus:outline-none focus:border-cyan-400 transition-all"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>
          <div className="mb-4">
            <label className="block text-cyan-300 font-semibold mb-2">Password</label>
            <div className="relative">
              <input
                type={showPassword ? "text" : "password"}
                className="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/20 text-white focus:outline-none focus:border-cyan-400 transition-all"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
              <button
                type="button"
                className="absolute right-2 top-2 text-white"
                onClick={() => setShowPassword((prev) => !prev)}
                tabIndex={-1}
              >
                {showPassword ? "🙈" : "👁️"}
              </button>
            </div>
          </div>
          {error && <div className="text-red-400 mb-2 text-center">{error}</div>}
          <button
            type="submit"
            className="w-full bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-semibold py-3 rounded-lg btn-futuristic shadow-lg transition-all"
          >
            Login
          </button>
          <button
            type="button"
            onClick={handleFingerprintLogin}
            disabled={fingerprintLoading}
            className="w-full mt-3 bg-gradient-to-r from-emerald-600 to-green-600 hover:from-emerald-700 hover:to-green-700 text-white font-semibold py-3 rounded-lg btn-futuristic shadow-lg transition-all disabled:opacity-50"
          >
            {fingerprintLoading ? "Waiting for fingerprint..." : "Login with Fingerprint"}
          </button>
        </form>
        <p className="text-xs text-gray-300 text-center mt-3">
          Supports Windows Hello / fingerprint credentials
        </p>
        <div className="text-center mt-4">
          <span className="text-gray-300">Don't have an account?</span>
          <button
            className="ml-2 text-cyan-400 hover:text-cyan-300 transition-colors"
            onClick={() => navigate("/register")}
          >
            Register
          </button>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
