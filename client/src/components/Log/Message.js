import React from 'react'

export default function Message({message, error}) {
    if(message.includes(error) || message.includes('STACK OVERFLOW'))
      return (<div style={{ border: '1px solid white', padding: '0.3rem', marginBottom: '0.2rem'}}>{message}</div>)
    else
      return (<div style={{paddingBottom: '0.5rem'}}>{message}</div>)
}
