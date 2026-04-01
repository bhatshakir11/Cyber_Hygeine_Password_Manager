import React, { useState, useEffect } from "react";
import Navbar from "../components/Navbar";
import AnimatedBackground from "../components/AnimatedBackground";
import apiClient from "../apiClient";

const NotesPage = () => {
  const [notes, setNotes] = useState([]);
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState({ title: "", content: "" });

  useEffect(() => {
    apiClient.get("/notes").then((res) => {
      setNotes(res.data);
    });
  }, []);

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleAdd = async (e) => {
    e.preventDefault();
    const res = await apiClient.post("/notes", form);
    if (res.data?.note) {
      setNotes((current) => [...current, res.data.note]);
    }
    setShowAdd(false);
    setForm({ title: "", content: "" });
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-blue-900 to-purple-900">
      <AnimatedBackground />
      <Navbar />
      <div className="max-w-5xl mx-auto py-8 px-4 sm:px-6 lg:px-8 relative z-10">
        <h2 className="text-4xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent mb-8 animate-fade-in">Encrypted Notes</h2>
        <button
          className="mb-6 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white px-6 py-3 rounded-lg btn-futuristic shadow-lg transition-all"
          onClick={() => setShowAdd(true)}
        >
          Add Note
        </button>
        {showAdd && (
          <form onSubmit={handleAdd} className="glass-card rounded-2xl p-6 mb-6 animate-fade-in">
            <div className="mb-4">
              <label className="block text-cyan-300 font-semibold mb-2">Title</label>
              <input name="title" value={form.title} onChange={handleChange} required className="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/20 text-white focus:outline-none focus:border-cyan-400 transition-all" />
            </div>
            <div className="mb-4">
              <label className="block text-cyan-300 font-semibold mb-2">Content</label>
              <textarea name="content" value={form.content} onChange={handleChange} required className="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/20 text-white focus:outline-none focus:border-cyan-400 transition-all min-h-[120px]" />
            </div>
            <button type="submit" className="bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white px-6 py-3 rounded-lg btn-futuristic shadow-lg transition-all">Save</button>
            <button type="button" className="ml-3 bg-gradient-to-r from-gray-600 to-gray-700 hover:from-gray-700 hover:to-gray-800 text-white px-6 py-3 rounded-lg btn-futuristic shadow-lg transition-all" onClick={() => setShowAdd(false)}>Cancel</button>
          </form>
        )}
        <div className="glass-card rounded-2xl p-6 animate-fade-in">
          <ul className="text-white space-y-4">
            {notes.map((note) => (
              <li key={note.id} className="p-4 bg-white/5 rounded-lg border border-white/10 hover:bg-white/10 transition-all">
                <span className="font-bold text-cyan-300 text-lg">{note.title}:</span> <span className="text-gray-200">{note.content}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
};

export default NotesPage;
