const express = require('express');
const app = express();
const cors = require('cors');
const axios = require('axios');
const session = require("express-session");
const cookieParser=require("cookie-parser")
const port = 5000;
const bodyParser = require('body-parser');
let email;
var token=null;
app.use(cookieParser())
app.use(cors({
  origin:["http://localhost:3000"],
  methods:["POST","GET"],
  credentials:true
}))
app.use(express.json());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret:'secret',
  resave:false,
  saveUninitialized:false,
  cookie:{
    secure:false,
    maxAge:1000*60*60*24
  }
}))

// Signup route
app.post('/api/signup', (req, res) => {
    const apiUrl = 'https://api.sandbox.stylopay.com/CognitoAPIs/api/v1/AuthServices/signUp';
    const headers = {
      'x-api-key': 'mv6uQwbi6Yb1wazN9TeY7q90uZrLPP119kwBZPz7'
    };
    email=req.body.email
    const requestBody = {
      'email': req.body.email,
      'password': req.body.password,
      'phoneNumber': req.body.phone,
      'clientId': "a3oce0b3g9og13gta0436qnjd",
      'userPoolId': "us-east-1_GgpUDOiMn",
      'customAttributes': {
        'profile': "student", // students-student, counsellors-counsellor, agents-agent, admins-admin
        'first_name': "",
        'isd_code': "",
        'last_name': "",
        'dob': ""
      }
    };
    console.log("request :-", requestBody)
    // console.log("requestbody",requestBody)
  
    axios.post(apiUrl, requestBody, { headers })
      .then((response) => {
        // Handle the successful response here
        console.log(response.data);
        res.send(response.data);
    })
      .catch((error) => {
        // Handle any errors here
        console.error('Request failed:', error);
        res.status(error.response ? error.response.status : 500).send(error.message);
      });
  });

//OTP route
app.post("/api/otp",(req,res)=>{
    const apiUrl = 'https://api.sandbox.stylopay.com/CognitoAPIs/api/v1/AuthServices/confirmSignUp';
          const requestBody= {
            'email':email,
            'clientId': "a3oce0b3g9og13gta0436qnjd",
            'userPoolId': "us-east-1_GgpUDOiMn",
            "emailOTP": req.body.otp
          };
          console.log("request2:-",requestBody)
          axios.post(apiUrl, requestBody).then((response)=>{
          res.send(response.data)
          })
          .catch((error) => {
            // Handle any errors here
            console.error('Request failed:', error);
            res.status(error.response ? error.response.status : 500).send(error.message);
          });
  })

//resendotp route
app.post("/api/resendOTP",(req,res)=>{
    const apiUrl = 'https://api.sandbox.stylopay.com/CognitoAPIs/api/v1/AuthServices/resendConfirmationCode';
          const requestBody= {
            'email': email,
            'clientId': "a3oce0b3g9og13gta0436qnjd",
            'userPoolId': "us-east-1_GgpUDOiMn",
          };
          axios.post(apiUrl,requestBody).then((response)=>{
  
            res.send(response.data)
          })
          .catch((error) => {
            // Handle any errors here
            console.error('Request failed:', error);
            res.status(error.response ? error.response.status : 500).send(error.message);
          });
  })

// login route
app.post("/api/login",async(req,res)=>{
  console.log("token++",token)
    if(!token){
      token = await refreshAccessToken();
      console.log("token1",token) // Use await with async function.
      console.log(1);
      }
    else if (await isTokenExpired(token)) {
      // If the token is expired, refresh it or handle accordingly
      token = await refreshAccessToken();
      console.log("token2",token) 
       // Use await with async function.
      console.log(2);
    }
    const apiUrl = 'https://api.sandbox.stylopay.com/CognitoAPIs/api/v1/AuthServices/signIn';
      const requestBody= {
        'username':req.body.email,
        'clientId': "a3oce0b3g9og13gta0436qnjd",
        'userPoolId': "us-east-1_GgpUDOiMn",
        "password": req.body.password
      };
      console.log("request2:-",requestBody)
      await axios.post(apiUrl, requestBody).then((response)=>{
          req.session.username=req.body.email
          console.log("req.session.username",req.session.username)
          console.log(3)
          res.send(response.data)
      })
      .catch((error) => {
        // Handle any errors here
        console.error('Request failed:', error);
        res.status(error.response ? error.response.status : 500).send(error.message);
      });

    async function refreshAccessToken() {
      const api_Url = "https://accounts.zoho.eu/oauth/v2/token";
      const request_Body={
        'client_id': "1000.6GP4EGM1XX8TL9LUMCAD3HPPHPKJEG",
        'client_secret': "d1815120780298b7328c8b49b1ab6b1e6c3fbb4cc7",
        "refresh_token":"1000.61395afad18e11d5f28d3133768b9970.c8a67471497115967da43bfcad9c9313",
        "grant_type":"refresh_token"
      };
      const headers ={
        'Content-Type': 'application/x-www-form-urlencoded',
      }
      try {
        const response = await axios.post(api_Url, request_Body, { headers });
        console.log("_response", response.data);
        return response.data["access_token"];
      } catch (error) {
        // Handle any errors here
        console.error('Request failed:', error);
        throw error;
      }
    }

    async function isTokenExpired(token) {
      console.log(2)
      const apiUrl = 'https://www.zohoapis.eu/crm/v3/Contacts/469374000004293002/Deals';
          const _headers = {
          'Authorization': `Zoho-oauthtoken ${token}`
          };
          console.log("_headers",_headers) 
          const params = {
          fields: 'Full_Name,Country,Course_Duration,Account_Name,Email,Contact_Name,Stage,Course,Preferred_University_Universities,Closing_Date,Course_Opted,Level1,Duration1,University1,University,Select_Program,Preferred_intake,Last_Qualification,English_Language_Certificate_IF_ANY,IELTS_PTE_score,Disability_or_Impairment,If_Yes_please_provide_details,How_did_you_hear_about_TEMC,Were_you_introduced_to_TEMC_by_and_Agent_or_a_Coun,JOB_Experience,Acknowledgement,If_YES_Insert_the_AGENT_IDENTIFICATION,Offer_Letter_Counsellor,Offer_Letter_Student,Terms_and_conditions,Please_upload_photo_identification_of_yourself,Privacy_Policy,Academic_Transcript,Upload_English,Electronic_signature,Date,Course_Level1,Course_Status',
          };
          await axios.get(apiUrl,{params: params, headers:_headers }).then((response)=>{
            if(response.data){
            console.log("response",response)
            console.log("response.data",response.data);
            return false
            }
            else{
              return true
            }
          }).catch((error) => {
            // Handle any errors here
            return error
        });
      }   
})

// session handling 
console.log("session_token",session)
app.use("/api/session",(req,res)=>{
  if(req.session.username){
    console.log(true)
    return res.json({valid : true,username:req.session.username})
  }
  else{
    console.log(false)
    return res.json({valid : false})
  }
})

// fecth course api with the help of access token
app.get("/api/course",(req,res)=>{

    const api_Url = "https://accounts.zoho.eu/oauth/v2/token";
    const request_Body={
    'client_id': "1000.6GP4EGM1XX8TL9LUMCAD3HPPHPKJEG",
    'client_secret': "d1815120780298b7328c8b49b1ab6b1e6c3fbb4cc7",
    "refresh_token":"1000.61395afad18e11d5f28d3133768b9970.c8a67471497115967da43bfcad9c9313",
    "grant_type":"refresh_token"
    };
    const headers ={
    'Content-Type': 'application/x-www-form-urlencoded',
    };
    axios.post(api_Url, request_Body,{headers}).then((_response)=>{
        const responseData = _response.data["access_token"];
        console.log("responseData",responseData)

        const apiUrl = 'https://www.zohoapis.eu/crm/v3/Course';
        const _headers = {
        'Authorization': `Zoho-oauthtoken ${responseData}`
        };
        console.log("_headers",_headers) 
        const params = {
        fields: 'Name,Course_URL,University,Duration,Department,Educational_Qualification,Creator_ID,Course_Fee,Course_Level,Country,Course_Description,Course_level,Requirement',
        };

        axios.get(apiUrl,{params: params, headers:_headers })
        .then((response) => {
            // Handle the successful response here
            console.log("response",response)
            console.log("response.data",response.data);
            res.send(response.data);
        })
        .catch((error) => {
            // Handle any errors here
            console.error('Request failed:', error);
            res.status(error.response ? error.response.status : 500).send(error.message);
        });
    })
    .catch((error) => {
        // Handle any errors here
        console.error('Request failed:', error);
        res.status(error.response ? error.response.status : 500).send(error.message);
    });
  })

  // fecth Application api with the help of access token
  app.get("/api/application",(req,res)=>{
    const api_Url = "https://accounts.zoho.eu/oauth/v2/token";
    const request_Body={
    'client_id': "1000.6GP4EGM1XX8TL9LUMCAD3HPPHPKJEG",
    'client_secret': "d1815120780298b7328c8b49b1ab6b1e6c3fbb4cc7",
    "refresh_token":"1000.61395afad18e11d5f28d3133768b9970.c8a67471497115967da43bfcad9c9313",
    "grant_type":"refresh_token"
    };
    const headers ={
    'Content-Type': 'application/x-www-form-urlencoded',
    };
    axios.post(api_Url, request_Body,{headers}).then((_response)=>{
        const responseData = _response.data["access_token"];
        console.log("responseData",responseData)

        const apiUrl = 'https://www.zohoapis.eu/crm/v3/Contacts/469374000004293002';
        const _headers = {
        'Authorization': `Zoho-oauthtoken ${responseData}`
        };
        console.log("_headers",_headers) 
        const params = {
        fields: 'Full_Name,Account_Name,Email,Phone,Owner',
        };

        axios.get(apiUrl,{params: params, headers:_headers })
        .then((response) => {
            // Handle the successful response here
            const apiUrl = 'https://www.zohoapis.eu/crm/v3/Contacts/469374000004293002/Deals';
            const _headers = {
            'Authorization': `Zoho-oauthtoken ${responseData}`
            };
            console.log("_headers",_headers) 
            const params = {
            fields: 'Full_Name,Country,Course_Duration,Account_Name,Email,Contact_Name,Stage,Course,Preferred_University_Universities,Closing_Date,Course_Opted,Level1,Duration1,University1,University,Select_Program,Preferred_intake,Last_Qualification,English_Language_Certificate_IF_ANY,IELTS_PTE_score,Disability_or_Impairment,If_Yes_please_provide_details,How_did_you_hear_about_TEMC,Were_you_introduced_to_TEMC_by_and_Agent_or_a_Coun,JOB_Experience,Acknowledgement,If_YES_Insert_the_AGENT_IDENTIFICATION,Offer_Letter_Counsellor,Offer_Letter_Student,Terms_and_conditions,Please_upload_photo_identification_of_yourself,Privacy_Policy,Academic_Transcript,Upload_English,Electronic_signature,Date,Course_Level1,Course_Status',
            };
            axios.get(apiUrl,{params: params, headers:_headers }).then((response)=>{
              console.log("response",response)
              console.log("response.data",response.data);
              res.send(response.data);
            }).catch((error) => {
              // Handle any errors here
              console.error('Request failed:', error);
              res.status(error.response ? error.response.status : 500).send(error.message);
          });
        })
        .catch((error) => {
            // Handle any errors here
            console.error('Request failed:', error);
            res.status(error.response ? error.response.status : 500).send(error.message);
        });
    })
    .catch((error) => {
        // Handle any errors here
        console.error('Request failed:', error);
        res.status(error.response ? error.response.status : 500).send(error.message);
    });
  })



app.listen(port, () => {
    console.log(`app listening on port ${port}`)
  })