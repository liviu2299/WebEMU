import React, { Suspense, lazy } from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import { ThemeProvider } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { theme } from "./styles"

const Home = lazy(() => import("./routes/Home"));

function App() {

    return (
        <ThemeProvider theme={theme}>
        <CssBaseline />
        <Router>
            <Suspense fallback={<div>Loading...</div>}>
                <Routes>
                    <Route path="/" element={<Home />} />
                </Routes>
            </Suspense>
        </Router>
        </ThemeProvider>
    );
}

export default App;
