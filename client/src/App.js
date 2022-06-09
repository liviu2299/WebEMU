import React, { Suspense, lazy } from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';

const Home = lazy(() => import("./routes/Home"));
const TextEditor = lazy(() => import("./routes/TextEditor"))

const theme = createTheme({
    palette: {
      type: 'dark',
      primary: {
        main: '#263238',
        contrastText: '#fff',
      },
      secondary: {
        main: '#2196f3',
      },
      background: {
        default: '#303030',
        paper: '#263238',
      },
        text: {
      primary: '#F3F3F3',
    },
    },
  });

function App() {

    return (
        <ThemeProvider theme={theme}>
        <CssBaseline />
        <Router>
            <Suspense fallback={<div>Loading...</div>}>
                <Routes>
                    <Route path="/" element={<Home />} />
                    <Route path="/editor" element={<TextEditor />} />
                </Routes>
            </Suspense>
        </Router>
        </ThemeProvider>
    );
}

export default App;
