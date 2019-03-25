//simple dummy server that sends JSON object

const express = require('express')
const path= require('path')
const router = express.Router()
const app = express()
const port = 3000

//var scriptPath = path.join(__dirname, 'script');

//dummy data
sesssion_data = [{"Id":"45856","Type":"ICMP"},{"Id":"45857","Type":"ICMP"}]

json_data = {

'TS':    [10, 20, 30, 40, 50, 60],
'RTT':   [30, 200, 100, 400, 150, 250],
'L-RTT': [50, 20, 10, 40, 15, 25],
'R-RTT': [30, 50, 30, 10, 55, 35],
'M-RTT': [70, 30, 40, 10, 35, 25]
};


function sendMeasurements(req, res){

	//res.header("Content-Type", "appliction/json")
	res.header("Access-Control-Allow-Origin", "*")
	//res.header("Access-Control-Allow-Headers", Content-Type")
	res.json(json_data)

}

function sendSessionData(req,res){
	res.header("Access-Control-Allow-Origin", "*")
	//res.header("Access-Control-Allow-Headers", Content-Type")
	res.json(sesssion_data)
}

//routes
//data fetching
router.get('/json_data', function (req, res) {
	sendMeasurements(req,res)

})

router.get('/demo', function (req, res) {
	sendSessionData(req,res)

})

//indexing
router.get('/index', function(req, res) {
    res.sendFile(path.join(__dirname + '/index.html'));
});

router.get('/rtt_data', function(req, res) {
    res.sendFile(path.join(__dirname + '/rtt_data.js'));
});

//static content
//app.use(express.static(scriptPath));
//app.use(express.static('script'));
//app.use("/script", express.static(__dirname + '/public'));

//router
app.use('/', router);

//service deploy
app.listen(port, () => console.log(`Example app listening on port ${port}!`))