import React from 'react'

import './Editor.css';

export default function Editor({ placeHolder, onChange }) {
  return (
    <div>
        <textarea
            className = "editor"
            placeholder= { placeHolder }
            onChange = { onChange }
        ></textarea>
    </div>
  )
}
