import React, { useState, useEffect, useRef } from 'react'
import {Controlled as CodeMirror} from 'react-codemirror2'
import 'codemirror/addon/selection/active-line'

import 'codemirror/lib/codemirror.css'
import 'codemirror/theme/material.css'

import 'codemirror/mode/gas/gas'

import './Code.css'
import { isEmpty } from '../../utils/utils'

let lastHighlightedLine = -1;

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

	function onCursorChange(editor, data){
		//for(let i=0; i<editor.lineCount(); i++) editor.doc.removeLineClass(i, 'background', 'current-line')
		if(lastHighlightedLine !== -1) editor.doc.removeLineClass(lastHighlightedLine, 'background', 'current-line')
		editor.doc.addLineClass(data.line, 'background', 'current-line')
		lastHighlightedLine = data.line
	}

	function clearHighlights(editor){
		//for(let i=0; i<editor.lineCount(); i++) editor.doc.removeLineClass(i, 'background', 'current-line')
		if(lastHighlightedLine !== -1) editor.doc.removeLineClass(lastHighlightedLine, 'background', 'current-line')
	}

	useEffect(() => {
		if(!isEmpty(emulator_data.STEP_INFO)){
			const addr = Number(emulator_data.STEP_INFO["address"])
			const line = emulator_data.EDITOR_MAPPING[addr.toString()]
			
			if(lastHighlightedLine !== -1) editorRef.current.editor.doc.removeLineClass(lastHighlightedLine, 'background', 'current-line')
			editorRef.current.editor.doc.addLineClass(line, 'background', 'current-line')
			lastHighlightedLine = line

		}
		if(isEmpty(emulator_data.STEP_INFO))
			if(lastHighlightedLine !== -1) 
				editorRef.current.editor.doc.removeLineClass(lastHighlightedLine, 'background', 'current-line')
	}, [emulator_data.STEP_INFO])

	useEffect(() => {
		if(emulator_data.ERROR_LINE !== "None"){
			if(lastHighlightedLine !== -1) editorRef.current.editor.doc.removeLineClass(lastHighlightedLine, 'background', 'current-line')
			editorRef.current.editor.doc.addLineClass(emulator_data.ERROR_LINE, 'gutter', 'error')
		}
		if(emulator_data.ERROR_LINE === "None") 
			if(lastHighlightedLine !== -1) 
				editorRef.current.editor.doc.removeLineClass(lastHighlightedLine, 'gutter', 'error')
	}, [emulator_data.ERROR_LINE])

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
			onBlur={editor => clearHighlights(editor)}
			onCursor={(editor, data) => onCursorChange(editor, data)}
		/>
  )
}
