import React, { Suspense, lazy } from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";

const Home = lazy(() => import("./routes/Home"));
const Test = lazy(() => import("./routes/Test"));
const TextEditor = lazy(() => import("./routes/TextEditor"))

function App() {

    return (
        <Router>
            <Suspense fallback={<div>Loading...</div>}>
                <Routes>
                    <Route path="/" element={<Home />} />
                    <Route path="/test" element={<Test />} />
                    <Route path="/editor" element={<TextEditor />} />
                </Routes>
            </Suspense>
        </Router>
    );
}

export default App;
