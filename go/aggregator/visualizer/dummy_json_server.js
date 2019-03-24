//simple dummy server that sends JSON object

const express = require('express')
const path= require('path')
const router = express.Router()
const app = express()
const port = 3000

json_data = {


'TS':    [10, 20, 30, 40, 50, 60],
'RTT':   [30, 200, 100, 400, 150, 250],
'L-RTT': [50, 20, 10, 40, 15, 25],
'R-RTT': [30, 50, 30, 10, 55, 35],
'M-RTT': [70, 30, 40, 10, 35, 25]
};

// json_data = {
//'session-ID': 'test id',
// 	'RTT': [30, 200, 100, 400, 150, 250],
// 	'L-RTT': [50, 20, 10, 40, 15, 25]
// };

function handleJsonReq(req, res){

	//res.header("Content-Type", "appliction/json")
	res.header("Access-Control-Allow-Origin", "*")
	res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
	res.json(json_data)

}


router.get('/json_data', function (req, res) {
	handleJsonReq(req,res)

})

router.get('/index', function(req, res) {
    res.sendFile(path.join(__dirname + '/index.html'));
});

app.use(express.static(__dirname + '/css'));
app.use('/', router);

app.listen(port, () => console.log(`Example app listening on port ${port}!`))