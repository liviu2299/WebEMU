import React from "react";
import {Responsive, WidthProvider } from "react-grid-layout";

import "./Layout.css"

export default function Home() {

    const ResponsiveGridLayout = WidthProvider(Responsive);

    const layout = [
        { i: "Editor", x: 0, y: 0, w: 5, h: 2, static: true },
        { i: "Registers", x: 5, y: 0, w: 3, h: 2 },
        { i: "Flags", x: 8, y: 0, w: 2, h: 2 },
        { i: "Memory", x: 0, y: 2, w: 6, h: 2, static: true },
        { i: "Stack", x: 8, y: 2, w: 4, h: 2, static: true }
    ];

    const layouts = {
        lg: layout
    }
    
    return (
            <ResponsiveGridLayout
                className="container"
                layouts={layouts}
                breakpoints={{ lg: 1200, md: 996, sm: 768, xs: 480, xxs: 0 }}
                cols={{ lg: 10, md: 10, sm: 6, xs: 4, xxs: 2 }}
                compactType="horizontal"
                maxRows={2}
            >
                <div style={{backgroundColor: 'powderblue'}} key="Editor">Editor</div>
                <div style={{backgroundColor: 'powderblue'}} key="Registers">Regs</div>
                <div style={{backgroundColor: 'powderblue'}} key="Flags">Flags</div>   
                <div style={{backgroundColor: 'powderblue'}} key="Memory">Memory</div>   
                <div style={{backgroundColor: 'powderblue'}} key="Stack">Stack</div>
            </ResponsiveGridLayout>
    )
}
