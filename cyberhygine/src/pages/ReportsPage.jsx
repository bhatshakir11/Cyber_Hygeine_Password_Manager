import React from "react";
import Navbar from "../components/Navbar";
import AnimatedBackground from "../components/AnimatedBackground";
import apiClient from "../apiClient";

const ReportsPage = () => {
  const handleDownload = async () => {
    try {
      const res = await apiClient.get("/report", { responseType: "blob" });
      const url = window.URL.createObjectURL(new Blob([res.data], { type: "application/pdf" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = "report.pdf";
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      alert("Failed to download report.");
    }
  };
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-blue-900 to-purple-900">
      <AnimatedBackground />
      <Navbar />
      <div className="max-w-3xl mx-auto py-8 px-4 sm:px-6 lg:px-8 relative z-10">
        <h2 className="text-4xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent mb-8 animate-fade-in">Reports</h2>
        <div className="glass-card rounded-2xl p-8 flex flex-col items-center animate-fade-in">
          <p className="text-gray-200 text-lg mb-3 text-center">
            Download your cyber hygiene report as a PDF.
          </p>
          <p className="text-cyan-100/80 text-sm mb-6 text-center max-w-2xl">
            Your report now includes a personalized security summary, key findings, and a ranked fix-first section based on weak and reused passwords in your vault.
          </p>
          <button
            onClick={handleDownload}
            className="bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white px-8 py-4 rounded-lg font-semibold btn-futuristic shadow-lg transition-all text-lg"
          >
            Download PDF Report
          </button>
        </div>
      </div>
    </div>
  );
};

export default ReportsPage;
