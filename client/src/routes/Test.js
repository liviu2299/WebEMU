import {useState, useEffect} from "react";

import Editor from '../components/Editor';

export default function Test() {

    const [input, setInput] = useState({});
    const [output, setOutput] = useState({});

    /*useEffect(() => {
        (async () => {
            const rawResponse = await fetch("/", {
                method: "POST",
                headers: {
                    Accept: "application/json",
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ "data": "mov eax, 3" }),
            });
            const content = await rawResponse.json();

            console.log(content);
        })();
    }, []);*/

    const handleSubmit = () => {
        (async () => {
            const rawResponse = await fetch("/", {
                method: "POST",
                headers: {
                    Accept: "application/json",
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ data: input }),
            });

            const content = await rawResponse.json();

            setOutput(content);
            console.log(output)

        })();
    }

    return (
        <div>
            <Editor
                placeHolder = "Type your code here"
                onChange = {(e) => setInput(e.target.value)}
            />
            <button onClick={ handleSubmit }>Submit</button>
            <div>

            </div>
        </div>
    );
}
