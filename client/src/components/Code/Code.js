import React, { useState, useEffect } from 'react'
import {Controlled as CodeMirror} from 'react-codemirror2'

import 'codemirror/lib/codemirror.css'
import 'codemirror/theme/material.css'

import './Code.css'

export default function Code(props) {
	
	const {
		value,
		onChange
	} = props

	function handleChange(editor, data, value){
		onChange(value)
	}

	function test(editor, data){
		console.log("----")
		console.log(editor)
		console.log("----")
		console.log(data.line+1 + ": " + editor.getLine(data.line) )
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
					lineNumbers: true,
				}}
				
			/>
  )
}
