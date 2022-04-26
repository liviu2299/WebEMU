import React, { useState, useEffect } from 'react'
import {Controlled as CodeMirror} from 'react-codemirror2'

import 'codemirror/lib/codemirror.css'
import 'codemirror/theme/material.css'

import 'codemirror/mode/gas/gas'

import './Code.css'

export default function Code(props) {
	
	const {
		value,
		onChange
	} = props

	function handleChange(editor, data, value){
		onChange(value)
	}

	function onClick(editor, data){
		//console.log("----")
		//console.log(data.line+1 + ": " + editor.getLine(data.line) )
	}

	/*
	useEffect(() => {
		console.log(code)
	}, [code])*/

  return (
			<CodeMirror
				onBeforeChange={handleChange}
				value={value}
				options={{
					lineWrapping: true,
					theme: 'material',
					mode: {name: 'gas', architecture:"x86"},
					lineNumbers: true,
				}}
				onCursor={onClick}
			/>
  )
}
