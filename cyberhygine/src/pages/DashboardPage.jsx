import React, { useCallback, useEffect, useMemo, useState } from "react";
import Navbar from "../components/Navbar";
import AnimatedBackground from "../components/AnimatedBackground";
import apiClient from "../apiClient";
import { registerFingerprint, supportsWebAuthn } from "../utils/webauthn";
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Legend } from "recharts";

const STRENGTH_COLORS = {
  Strong: "#04c956",
  Medium: "#e8a11c",
  Weak: "#f75929",
};

const DashboardPage = () => {
  const [stats, setStats] = useState({ strong: 0, weak: 0, medium: 0, score: 0, reused: 0, unique: 0 });
  const [credentials, setCredentials] = useState([]);
  const [fingerprints, setFingerprints] = useState([]);
  const [fingerprintError, setFingerprintError] = useState("");
  const [fingerprintSuccess, setFingerprintSuccess] = useState("");
  const [fingerprintLoading, setFingerprintLoading] = useState(false);
  const [deletingFingerprintId, setDeletingFingerprintId] = useState("");
  const [dashboardLoading, setDashboardLoading] = useState(true);

  const fetchFingerprints = useCallback(async () => {
    try {
      const res = await apiClient.get("/fingerprints");
      setFingerprints(res.data.fingerprints || []);
      setFingerprintError("");
    } catch (err) {
      setFingerprintError("Failed to load fingerprints.");
    }
  }, []);

  const fetchDashboardData = useCallback(async () => {
    setDashboardLoading(true);
    try {
      const [dashboardRes, credentialsRes, fingerprintsRes] = await Promise.all([
        apiClient.get("/dashboard"),
        apiClient.get("/credentials"),
        apiClient.get("/fingerprints")
      ]);
      setStats(dashboardRes.data);
      setCredentials(credentialsRes.data);
      setFingerprints(fingerprintsRes.data.fingerprints || []);
      setFingerprintError("");
    } catch (err) {
      setFingerprintError("Failed to load dashboard data.");
    } finally {
      setDashboardLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDashboardData();

    const refreshOnFocus = () => {
      fetchDashboardData();
    };
    const refreshOnVisibility = () => {
      if (document.visibilityState === "visible") {
        fetchDashboardData();
      }
    };

    window.addEventListener("focus", refreshOnFocus);
    document.addEventListener("visibilitychange", refreshOnVisibility);
    return () => {
      window.removeEventListener("focus", refreshOnFocus);
      document.removeEventListener("visibilitychange", refreshOnVisibility);
    };
  }, [fetchDashboardData]);

  const handleAddFingerprint = async () => {
    setFingerprintSuccess("");
    setFingerprintError("");
    if (!supportsWebAuthn()) {
      setFingerprintError("Fingerprint login is not supported in this browser.");
      return;
    }
    setFingerprintLoading(true);
    try {
      await registerFingerprint();
      await fetchFingerprints();
      setFingerprintSuccess("New fingerprint added.");
    } catch (err) {
      setFingerprintError("Fingerprint registration failed.");
    } finally {
      setFingerprintLoading(false);
    }
  };

  const handleDeleteFingerprint = async (credentialId) => {
    setFingerprintSuccess("");
    setFingerprintError("");
    const confirmed = window.confirm("Remove this fingerprint?");
    if (!confirmed) return;
    setDeletingFingerprintId(credentialId);
    try {
      await apiClient.delete(`/fingerprints/${encodeURIComponent(credentialId)}`);
      await fetchFingerprints();
      setFingerprintSuccess("Fingerprint removed.");
    } catch (err) {
      setFingerprintError("Failed to remove fingerprint.");
    } finally {
      setDeletingFingerprintId("");
    }
  };

  const hygieneScore = stats.score;
  const passwordStats = useMemo(() => [
    { name: "Strong", value: stats.strong },
    { name: "Medium", value: stats.medium },
    { name: "Weak", value: stats.weak },
  ], [stats.strong, stats.medium, stats.weak]);
  const reusedStats = useMemo(() => [
    { name: "Reused", value: stats.reused },
    { name: "Unique", value: stats.unique },
  ], [stats.reused, stats.unique]);
  const COLORS = ["#00C49F", "#FF8042", "#FFD600"];

  const reminders = useMemo(() => {
    const items = [];
    const passwordMap = {};

    credentials.forEach((cred) => {
      if (passwordMap[cred.password]) {
        passwordMap[cred.password].push(cred.site);
      } else {
        passwordMap[cred.password] = [cred.site];
      }
      if (cred.strength === "weak") {
        items.push(`Weak password detected for ${cred.site}`);
      }
    });

    Object.values(passwordMap).forEach((sites) => {
      if (sites.length > 1) {
        items.push(`Password reused for: ${sites.join(", ")}`);
      }
    });

    return items.length > 0 ? items : ["All your passwords are strong and unique! Great job!"];
  }, [credentials]);

  const tips = useMemo(() => {
    const items = [];
    if (stats.weak > 0) items.push("Consider updating weak passwords to stronger ones.");
    if (stats.reused > 0) items.push("Avoid reusing passwords across sites.");
    if (stats.strong === 0) items.push("Try to use strong passwords for all accounts.");
    return items.length > 0 ? items : ["Your vault is in excellent shape!"];
  }, [stats.weak, stats.reused, stats.strong]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-blue-900 to-purple-900">
      <AnimatedBackground />
      <Navbar />
      <div className="max-w-7xl mx-auto py-8 px-4 sm:px-6 lg:px-8 relative z-10">
        <h2 className="text-4xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent mb-8 animate-fade-in">Dashboard</h2>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 lg:gap-8">
          <div className="glass-card rounded-2xl p-6 text-center animate-fade-in" style={{animationDelay: '0.1s'}}>
            <div className="flex items-center justify-between gap-4 mb-4">
              <h3 className="text-lg font-semibold text-cyan-300">Cyber Hygiene Score</h3>
              <button
                onClick={fetchDashboardData}
                className="rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-3 py-2 text-xs font-semibold text-cyan-100 transition-all hover:bg-cyan-500/20"
              >
                {dashboardLoading ? "Refreshing..." : "Refresh"}
              </button>
            </div>
            <div className="flex flex-col items-center">
              <PieChart width={180} height={180}>
                <Pie
                  data={[{ name: "Score", value: hygieneScore }, { name: "Rest", value: 100 - hygieneScore }]}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  startAngle={90}
                  endAngle={-270}
                  dataKey="value"
                >
                  <Cell key="score" fill="#00C49F" />
                  <Cell key="rest" fill="#22223b" />
                </Pie>
              </PieChart>
              <span className="text-4xl font-bold bg-gradient-to-r from-green-400 to-cyan-400 bg-clip-text text-transparent mt-2">{hygieneScore}%</span>
            </div>
          </div>
          <div className="glass-card rounded-2xl p-6 animate-fade-in" style={{animationDelay: '0.2s'}}>
            <h3 className="text-lg font-semibold text-cyan-300 mb-4">Password Strength</h3>
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={passwordStats}>
                <XAxis dataKey="name" stroke="#fff" />
                <YAxis stroke="#fff" />
                <Tooltip />
                <Legend />
                <Bar dataKey="value">
                  {passwordStats.map((entry, idx) => (
                    <Cell key={`cell-bar-${idx}`} fill={STRENGTH_COLORS[entry.name]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 lg:gap-8 mt-6 lg:mt-8">
          <div className="glass-card rounded-2xl p-6 animate-fade-in" style={{animationDelay: '0.3s'}}>
            <h3 className="text-lg font-semibold text-cyan-300 mb-4">Reused vs Unique Passwords</h3>
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie
                  data={reusedStats}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={70}
                  label
                >
                  {reusedStats.map((entry, idx) => (
                    <Cell key={`cell-${idx}`} fill={COLORS[idx % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="glass-card rounded-2xl p-6 flex flex-col justify-center animate-fade-in" style={{animationDelay: '0.4s'}}>
            <h3 className="text-lg font-semibold text-cyan-300 mb-4">Reminders & Alerts</h3>
            <ul className="text-gray-200 mb-4 space-y-2">
              {reminders.map((rem, idx) => (
                <li key={idx} className="flex items-start"><span className="text-cyan-400 mr-2">•</span>{rem}</li>
              ))}
            </ul>
            <h4 className="text-md font-semibold text-cyan-300 mb-2 mt-4">Tips:</h4>
            <ul className="text-gray-300 space-y-2">
              {tips.map((tip, idx) => (
                <li key={idx} className="flex items-start"><span className="text-blue-400 mr-2">→</span>{tip}</li>
              ))}
            </ul>
          </div>
        </div>
        <div className="glass-card rounded-2xl p-6 mt-6 lg:mt-8 animate-fade-in" style={{animationDelay: "0.5s"}}>
          <div className="flex items-center justify-between gap-4 flex-wrap">
            <h3 className="text-lg font-semibold text-cyan-300">Manage Fingerprints</h3>
            <button
              onClick={handleAddFingerprint}
              disabled={fingerprintLoading}
              className="bg-gradient-to-r from-emerald-600 to-green-600 hover:from-emerald-700 hover:to-green-700 text-white px-4 py-2 rounded-lg btn-futuristic shadow-lg transition-all disabled:opacity-50"
            >
              {fingerprintLoading ? "Waiting for fingerprint..." : "Add Fingerprint"}
            </button>
          </div>
          <p className="text-gray-300 mt-2 text-sm">
            Register and manage Windows Hello fingerprint credentials for biometric login.
          </p>
          {fingerprintError && <p className="text-red-400 mt-3 text-sm">{fingerprintError}</p>}
          {fingerprintSuccess && <p className="text-green-400 mt-3 text-sm">{fingerprintSuccess}</p>}
          <div className="mt-4 space-y-3">
            {fingerprints.length === 0 && (
              <p className="text-gray-300 text-sm">No fingerprints registered yet.</p>
            )}
            {fingerprints.map((item) => (
              <div key={item.credential_id} className="bg-white/5 border border-white/10 rounded-lg p-4 flex items-center justify-between gap-4 flex-wrap">
                <div>
                  <p className="text-white font-medium">{item.display_id}</p>
                  <p className="text-xs text-gray-300 mt-1">
                    Created: {item.created_at || "unknown"} | Sign count: {item.sign_count}
                  </p>
                  {item.transports?.length > 0 && (
                    <p className="text-xs text-cyan-300 mt-1">
                      Transports: {item.transports.join(", ")}
                    </p>
                  )}
                </div>
                <button
                  onClick={() => handleDeleteFingerprint(item.credential_id)}
                  disabled={deletingFingerprintId === item.credential_id}
                  className="bg-gradient-to-r from-red-600 to-pink-600 hover:from-red-700 hover:to-pink-700 text-white px-4 py-2 rounded-lg btn-futuristic shadow-lg transition-all disabled:opacity-50"
                >
                  {deletingFingerprintId === item.credential_id ? "Removing..." : "Remove"}
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default DashboardPage;
