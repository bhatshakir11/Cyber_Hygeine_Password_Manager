import React, { memo } from "react";

const AnimatedBackground = memo(() => {
  const blobs = [
    { size: 300, color: "#2D333B", top: "10%", left: "10%", delay: 0, duration: 11 },
    { size: 250, color: "#1F242C", top: "60%", left: "70%", delay: 2, duration: 14 },
    { size: 200, color: "#2D333B", top: "30%", left: "80%", delay: 4, duration: 13 },
    { size: 280, color: "#1F242C", top: "70%", left: "20%", delay: 6, duration: 15 },
    { size: 220, color: "#2D333B", top: "50%", left: "50%", delay: 8, duration: 10 },
    { size: 260, color: "#1F242C", top: "20%", left: "40%", delay: 10, duration: 14 },
    { size: 240, color: "#2D333B", top: "80%", left: "60%", delay: 12, duration: 13 },
    { size: 210, color: "#1F242C", top: "40%", left: "15%", delay: 14, duration: 11 },
    { size: 230, color: "#2D333B", top: "15%", left: "60%", delay: 1, duration: 13 },
    { size: 270, color: "#1F242C", top: "55%", left: "30%", delay: 3, duration: 12 },
    { size: 190, color: "#2D333B", top: "75%", left: "80%", delay: 5, duration: 15 },
    { size: 250, color: "#1F242C", top: "35%", left: "50%", delay: 7, duration: 11 },
  ];

  return (
    <div style={{ position: "fixed", top: 0, left: 0, width: "100%", height: "100%", overflow: "hidden", zIndex: 0, pointerEvents: "none", background: "#000000" }}>
      {blobs.map((blob, i) => (
        <div
          key={i}
          style={{
            position: "absolute",
            width: `${blob.size}px`,
            height: `${blob.size}px`,
            background: blob.color,
            top: blob.top,
            left: blob.left,
            borderRadius: "50%",
            filter: "blur(60px)",
            opacity: 0.15,
            animation: `paintFloat ${blob.duration}s infinite ease-in-out`,
            animationDelay: `${blob.delay}s`,
          }}
        />
      ))}
    </div>
  );
});

export default AnimatedBackground;
