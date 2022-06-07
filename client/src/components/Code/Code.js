import React, { useState, useEffect, useRef } from 'react'
import {Controlled as CodeMirror} from 'react-codemirror2'

import 'codemirror/lib/codemirror.css'
import 'codemirror/theme/material.css'

import 'codemirror/mode/gas/gas'

import './Code.css'
import { isEmpty } from '../../utils/utils'

export default function Code(props) {
	
	const {
		value,
		onChange,
		emulator_data
	} = props

	const editorRef = useRef(null)

	const getEditor = (editor) =>{
		editorRef.current = editor
	}

	function handleChange(editor, data, value){
		onChange(value)
	}

	useEffect(() => {
		if(!isEmpty(emulator_data.STEP_INFO)){
			const addr = Number(emulator_data.STEP_INFO["address"])
			const line = emulator_data.EDITOR_MAPPING[addr.toString()]
			console.log(line)

			editorRef.current.editor.doc.getAllMarks().forEach(marker => marker.clear())
			editorRef.current.editor.markText({line: line, ch: 0}, {line: line, ch: 100}, {className: "styled-background"})
		}
		if(isEmpty(emulator_data.STEP_INFO)) editorRef.current.editor.doc.getAllMarks().forEach(marker => marker.clear())
	}, [emulator_data.STEP_INFO])

  return (
		<CodeMirror ref={editorRef}
			onBeforeChange={handleChange}
			value={value}
			options={{
				lineWrapping: true,
				theme: 'material',
				mode: {name: 'gas', architecture:"x86"},
				lineNumbers: true,
			}}
			editorDidMount={editor => {getEditor(editor)}}
		/>
  )
}
