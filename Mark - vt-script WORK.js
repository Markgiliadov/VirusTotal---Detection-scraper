const printDict = (dict) => {
    for (let i = 0; i < JSON.stringify(dict).split(',').length; i++) {
        console.log("\t" + JSON.stringify(dict).split(',')[i]);
    }
}
const dataKeys = prompt("ENTER Vendor Names:");
const dataValues = prompt("ENTER Detection Names:");
const inputDataDict = []
const keys = JSON.stringify(dataKeys).split("\\r\\n")
keys[0] = keys[0].replaceAll(/"/g, "");
keys[keys.length - 1] = keys[keys.length - 1].replaceAll(/"/g, "");
const values = JSON.stringify(dataValues).split("\\r\\n")
values[0] = values[0].replaceAll(/"/g, "");
values[values.length - 1] = values[values.length - 1].replaceAll(/"/g, "");
//vt detections script start--
const originDoc = document.body.querySelectorAll('vt-ui-shell')[0].querySelectorAll("div")[1].querySelectorAll("file-view")[0].shadowRoot.querySelectorAll("vt-ui-main-generic-report")[0].querySelectorAll('.tab-slot')[0].querySelectorAll('vt-ui-detections-list')[0].shadowRoot.querySelectorAll("div");
const detectionsDict = {}
for (let i = 1; i < originDoc.length; i++) {
    const detection = originDoc[i].querySelectorAll("span")[2]?.className;
    const detectionKey = originDoc[i].querySelectorAll("span")[0]?.querySelectorAll("span")[0]?.innerText;
    const detectionVal = originDoc[i].querySelectorAll("span")[2]?.querySelectorAll('.individual-detection')[0]?.innerText;
    if (detection.includes('malicious result file')) {
        detectionsDict[detectionKey] = detectionVal;
    }
}
// printDict(detectionsDict);
//vt detections scrip end--
let index = 0;
for (let i = 0; i < keys.length; i++) {
    index++;
    keys[i] = keys[i].replaceAll(/"|\\r|\\t|\\n|\r|\n|\\/g, "").trim();
    values[i] = values[i].replaceAll(/"|\\r|\\t|\\n|\r|\n|\\/g, "").trim();
    const obj = new Object()
    obj[keys[i]] = values[i]
    inputDataDict.push(obj)
}
//inputDataDict ready from detections dashboard
//Test if new detections on virustotal!
const newDetectionsDict = {};
for ([key, value] of Object.entries(detectionsDict)) {
    newDetectionsDict[key.trim().toLowerCase()] = value.trim()
}
const oldDetectionsDict = {}
const numOfDetections = Object.keys(detectionsDict).length;
// console.log("found ",numOfDetections," detections!")
// console.log(JSON.stringify(newDetectionsDict))
const calc = async () => {
    let wasMatched = false;
    Object.values(inputDataDict).forEach(obj => {
        const vendor = Object.keys(obj)[0];
        const detection = Object.values(obj)[0];
        console.log(vendor, detection)
        wasMatched = false;
        let parsedKey = parseKey(vendor);
        // console.log('parsedkey: ', parsedKey);
        if (vendor.trim().length > 0 && detection.trim().length > 0) {
            for ([key, value] of Object.entries(detectionsDict)) {
                const parsedVTKey = parseKey(key);
                if (typeof parsedKey == 'object') {
                    if (typeof parsedVTKey == 'object') {
                        for (let i = 0; i < parsedKey.length; i++) {
                            console.log('1KEYPARSED: ' + parsedKey[i])
                            for (let k = 0; k < parsedVTKey.length; k++) {
                                if (parsedVTKey[k].toLowerCase().includes(parsedKey[i]) || (parsedKey[i] === parsedVTKey[k].toLowerCase())) {
                                    // console.log('VTKEYPARSED: ' + parsedVTKey[k])
                                    if (detection.toLowerCase().trim() === value.toLowerCase().trim()) {
                                        wasMatched = true;
                                        // console.log("match: "+parsedKey[i].toLowerCase()," vt detection1: ", key.toLowerCase(), "matched: " + wasMatched)
                                        delete newDetectionsDict[key.toLowerCase()]
                                        break;
                                    }
                                }
                            }
                            // console.log("detection: " + key + "inputDetection: " + parsedKey[i])
                            // if(wasMatched){
                            //     break
                            // }
                        }
                    } else if (typeof parsedVTKey == 'string') {
                        // console.log('2VTKEYPARSED: ' + parsedVTKey)
                        for (let i = 0; i < parsedKey.length; i++) {
                            console.log('2KEYPARSED: ' + parsedKey[i])
                            if (parsedVTKey.toLowerCase().includes(parsedKey[i]) || (parsedKey[i] === parsedVTKey.toLowerCase())) {
                                if (detection.toLowerCase().trim() === value.toLowerCase().trim()) {
                                    wasMatched = true;
                                    // console.log("match: "+parsedKey[i].toLowerCase()," vt detection2: ", key.toLowerCase(), "matched: " + wasMatched)
                                    delete newDetectionsDict[key.toLowerCase()]
                                    break;
                                }
                            }
                            // console.log("detection: " + key + "inputDetection: " + parsedKey[i])
                        }
                    }
                }
                else if (typeof parsedKey == 'string') {
                    if (typeof parsedVTKey == 'object') {
                        console.log('3KEYPARSED: ' + parsedKey)
                        for (let k = 0; k < parsedVTKey.length; k++) {
                            // console.log('3VTKEYPARSED: ' + parsedVTKey[k])
                            if (parsedKey.includes(parsedVTKey[k].toLowerCase()) || (parsedKey === parsedVTKey[k].toLowerCase())) {
                                if (detection.toLowerCase().trim() === value.toLowerCase().trim()) {
                                    wasMatched = true;
                                    // console.log("match: "+parsedKey[i].toLowerCase()," vt detection3: ", key.toLowerCase(), "matched: " + wasMatched)
                                    delete newDetectionsDict[key.toLowerCase()]
                                    break;
                                }
                            }
                        }
                        // console.log("detection: " + key + "inputDetection: " + parsedKey[i])
                    }
                    else if (typeof parsedVTKey == 'string') {
                        console.log('4KEYPARSED: ' + parsedKey)
                        if (parsedVTKey.toLowerCase().includes(parsedKey) || parsedKey.includes(parsedVTKey.toLowerCase()) || (parsedKey === parsedVTKey.toLowerCase())) {
                            if (detection.toLowerCase().trim() === value.toLowerCase().trim()) {
                                wasMatched = true;
                                // console.log("match: "+parsedKey[i].toLowerCase()," vt detection4: ", key.toLowerCase(), "matched: " + wasMatched)
                                delete newDetectionsDict[key.toLowerCase()]
                                break;
                            }
                        }
                        // console.log("detection: " + key + "inputDetection: " + parsedKey[i])
                    }
                }
            }
            // console.log('vendor:'+vendor+" det: " +detection+" match " +wasMatched)
            if (!wasMatched) {
                console.log('---delete start---')
                oldDetectionsDict[vendor] = detection
                printDict(oldDetectionsDict)
                console.log('---delete end---')
            }
        } else {
            console.log('err state', " vendor: ", vendor, " detection: ", detection)
        }
    })
}
const parseKey = (inputKey) => {
    let newInputKey = [];
    if (inputKey.includes('-')) {
        newInputKey = [];
        const splitInputKey = inputKey.split('-')
        for (let i = 0; i < splitInputKey.length; i++) {
            if (inputKey[i].match(/\s+/)) {
                const spaceSplitKey = splitInputKey[i].split(/\s+/)
                for (let k = 0; k < spaceSplitKey.length; k++) {
                    newInputKey.push(spaceSplitKey[i].trim().replaceAll(/[^a-zA-Z0-9]/g, '').toLowerCase())
                }
            } else {
                newInputKey.push(splitInputKey[i].trim().replaceAll(/[^a-zA-Z0-9]/g, '').toLowerCase())
            }
        }
    } else if (inputKey.match(/\s+/)) {
        newInputKey = [];
        const splitInputKey = inputKey.split(/\s+/)
        for (let k = 0; k < splitInputKey.length; k++) {
            newInputKey.push(splitInputKey[k].trim().replaceAll(/[^a-zA-Z0-9]/g, '').toLowerCase())
        }
    } else
        newInputKey = inputKey.trim().replaceAll(/[^a-zA-Z0-9]/g, '').toLowerCase();
    // console.log(JSON.stringify(newInputKey))
    return newInputKey;
}
await calc();
console.log("Found " + Object.keys(newDetectionsDict).length)
console.log("Total of ", numOfDetections - (Object.keys(newDetectionsDict).length), " detections were MATCHED!")
console.log("Total of not relevant: ", Object.keys(oldDetectionsDict).length)
for ([key, value] of Object.entries(oldDetectionsDict)) {
    console.log("NR: \n", "\n" + key.trim(), "\n", "\n" + value.trim())
}
console.log(Object.keys(newDetectionsDict).length, " new detections were revealed")
console.log("Add new detection: \n")
let finalOutput = "\n";
for ([key, value] of Object.entries(newDetectionsDict)) {
    finalOutput += "\t" + key.trim() + "\t" + value.trim() + "\n"
}
console.log(finalOutput)
