import {useState, useEffect} from "react";

import Editor from '../components/Editor';

export default function Test() {

    const [input, setInput] = useState({});
    const [output, setOutput] = useState({});

    const handleRun = () => {
        (async () => {
            const rawResponse = await fetch("/compute", {
                method: "POST",
                headers: {
                    Accept: "application/json",
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ data: input }),
            });

            const content = await rawResponse.json();

            setOutput(content);

        })();
    }

    const handleAssemble = () => {
        (async () => {
            const rawResponse = await fetch("/compile", {
                method: "POST",
                headers: {
                    Accept: "application/json",
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ data: input }),
            });

            const content = await rawResponse.json();

            setOutput(content);

        })();
    }

    useEffect(() => {
        console.log(output)
    }, [output])

    return (
        <div>
            <Editor
                placeHolder = "Type your code here"
                onChange = {(e) => setInput(e.target.value)}
            />
            <button onClick={ handleRun }>Run</button>
            <button onClick={ handleAssemble }>Assemble</button>
            <div>

            </div>
        </div>
    );
}
