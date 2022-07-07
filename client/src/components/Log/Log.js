import React, { useEffect, useRef } from 'react'

import Message from './Message';

import './Log.css'

export default function Log({logs, error}) {

  const divEndRef = useRef();

  function scrollToBottom() {
    divEndRef.current.scrollIntoView({ behavior: 'smooth' });
  }

  useEffect(() => {
    scrollToBottom();
  }, [logs])  

  return (
    <div className="logs">
    {logs.map((message, i) => 
        <div key={i}>
                <Message key={i} message={message} error={error}/>                      
        </div>
        )
    }
    <div ref={divEndRef} />
    </div>
);
}
