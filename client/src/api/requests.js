export const handleRun = (id,setEmulator,input,emulator,setLoading) => {
  (async () => {
      
      const rawResponse = await fetch("/compute", {
          method: "POST",
          headers: {
              Accept: "application/json",
              "Content-Type": "application/json",
          },
          body: JSON.stringify({ id: id, data: input }),
      });

      const content = await rawResponse.json();

      setLoading(false)

      if(content.error === "None")    
          setEmulator({...emulator, MEMORY: {...emulator.MEMORY, data:content.memory}, REGISTERS: content.registers, ERROR: content.error, LOG: content.log, STATE: content.state, STEP_INFO: content.step_info, EDITOR_MAPPING: content.editor_mapping, ERROR_LINE: content.error_line})
      else
          setEmulator({...emulator, ERROR: content.error, LOG: content.log, STATE: content.state, ERROR_LINE: content.error_line})


  })();
}

export const handleStep = (id,setEmulator,input,emulator) => {
(async () => {
    const rawResponse = await fetch("/step", {
        method: "POST",
        headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ id: id, data: input }),
    });

    const content = await rawResponse.json();

    if(content.error === "None")    
        setEmulator({...emulator, MEMORY: {...emulator.MEMORY, data:content.memory}, REGISTERS: content.registers, ERROR: content.error, LOG: content.log, STATE: content.state, STEP_INFO: content.step_info, EDITOR_MAPPING: content.editor_mapping, ERROR_LINE: content.error_line})
    else
        setEmulator({...emulator, ERROR: content.error, LOG: content.log, STATE: content.state, ERROR_LINE: content.error_line})

})();
}

export const handleAssemble = (id,setEmulator,input,emulator) => {
  (async () => {
      const rawResponse = await fetch("/compile", {
          method: "POST",
          headers: {
              Accept: "application/json",
              "Content-Type": "application/json",
          },
          body: JSON.stringify({ id: id, data: input }),
      });

      const content = await rawResponse.json();

      if(content.error === "None")   
          setEmulator({...emulator, MEMORY: {...emulator.MEMORY, data:content.memory}, REGISTERS: content.registers, ERROR: content.error, LOG: content.log, STATE: content.state, STEP_INFO: content.step_info, EDITOR_MAPPING: content.editor_mapping, ERROR_LINE: content.error_line})
      else
          setEmulator({...emulator, ERROR: content.error, LOG: content.log, STATE: content.state, ERROR_LINE: content.error_line})
  })();
} 

export const handleUpdateParameters = (client_id, options) => {
    (async () => {
        const rawResponse = await fetch("/update", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ id: client_id, data: options }),
        });
        
        console.log(JSON.stringify({ id: client_id, data: options }))
        const content = await rawResponse.json();
  
        console.log(content.message);
  
    })();
}

export const handleHome = (id) => {
    (async () => {
        const rawResponse = await fetch("/", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ id: id }),
        });
  
        const content = await rawResponse.json();
  
        console.log(content.message);
  
    })();
}  