// import module 
// base64
const express = require('express');
const app = express();
const cors = require('cors');
const axios = require('axios');
const session = require("express-session");
const cookieParser=require("cookie-parser")
const port = 5000;
const bodyParser = require('body-parser');

// create global variable 
let email;
var token=null;//define token

// use middleware 
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
app.post('/api/signup', async(req, res) => {
    // call cognitoapi for signup
    const apiUrl = 'https://api.sandbox.stylopay.com/CognitoAPIs/api/v1/AuthServices/signUp';
    const headers = {
      'x-api-key': 'mv6uQwbi6Yb1wazN9TeY7q90uZrLPP119kwBZPz7'
    };
    email=req.body.email
    const requestBody = {
      "fullName":req.body.fullName,
      'email': req.body.email,
      'password': req.body.password,
      'phoneNumber': `${req.body.countryCode}${req.body.phone}`,
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
    axios.post(apiUrl, requestBody, {headers: headers})
      .then(async(response) => {
        console.log(1)
        // Genrate token when token is null or expire.
        if(!token || await isTokenExpired(token)){  
          console.log(2)
            token = await refreshAccessToken();
          }
          var authToken = `Zoho-oauthtoken ${token}`
          // create  leads or prospect data
          const apiUrl = 'https://crmsandbox.zoho.eu/crm/v3/Leads';
          const headers = {
          'Authorization': authToken,
          'Content-Type': 'application/json'
          };
          const request_Body={
            "data": [
              {
                  "First_Name":requestBody["fullName"].split(" ").length<2 ? requestBody["fullName"] : requestBody["fullName"].substring(0, requestBody["fullName"].lastIndexOf(" ")),
                  "Last_Name": requestBody["fullName"].split(" ").length<2 ? "" : requestBody["fullName"].split(" ").pop(),
                  "Email": requestBody["email"],
                  "Phone": requestBody["phoneNumber"]
              }
          ],
          };
          axios.post(apiUrl, request_Body, {headers: headers} )
          .then((response) => {
            console.log("response1 :",response)
            console.log("response2 :",response.data.data[0].code)
            if (response.data.data[0].code==="SUCCESS"){
              // create the contact or student data 
              const apiUrl = 'https://crmsandbox.zoho.eu/crm/v3/Contacts';
              const _headers = {
              'Authorization': `Zoho-oauthtoken ${token}`
              };
              const request_Body={
                "data": [
                  {
                    "First_Name":requestBody["fullName"].split(" ").length<2 ? requestBody["fullName"] : requestBody["fullName"].substring(0, requestBody["fullName"].lastIndexOf(" ")),
                    "Last_Name": requestBody["fullName"].split(" ").length<2 ? "" : requestBody["fullName"].split(" ").pop(),
                    "Email": requestBody["email"],
                    "Phone": requestBody["phoneNumber"]
                  }
              ],
              };
              axios.post(apiUrl,request_Body,{headers: _headers}).then((response)=>{
                res.send(response.data);
              }).catch((error) => {
                // Handle any errors here
                console.error('Request failed:', error);
                res.status(error.response ? error.response.status : 500).send(error.message);
              });
            } 
             }).catch((error) => {
                // Handle any errors here
                console.error('Request failed:', error);
                res.status(error.response ? error.response.status : 500).send(error.message);
            });
          async function refreshAccessToken() {
            console.log(3)
            const api_Url = "https://accounts.zoho.eu/oauth/v2/token";
            const request_Body={
              'client_id': "1000.6GP4EGM1XX8TL9LUMCAD3HPPHPKJEG",
              'client_secret': "d1815120780298b7328c8b49b1ab6b1e6c3fbb4cc7",
              "refresh_token":"1000.632e06eb56b23a1e025aa3be6d6aee64.19fba570d04a1144edb0e33da9f05794",
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
            console.log(4)
            const apiUrl = 'https://www.zohoapis.eu/crm/v3/Contacts/469374000004293002/Deals';
                const _headers = {
                'Authorization': `Zoho-oauthtoken ${token}`,
                'Content-Type': 'application/json'
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
    if(!token || await isTokenExpired(token)){
      token = await refreshAccessToken();
      console.log("token1",token) // Use await with async function.
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
          if(!response.data.errorCode){
            const apiUrl = 'https://crmsandbox.zoho.eu/crm/v3/Contacts/search';
            const _headers = {
            'Authorization': `Zoho-oauthtoken ${token}`
            };
            const params = {
            fields: 'Full_Name,Email,Phone,Owner',
            criteria:`((Email:equals:${requestBody['username']}))`
            };
            axios.get(apiUrl,{params, headers:_headers })
            .then((response) => {
                // Handle the successful response here
                console.log("response",response)
                console.log("response.data",response.data);
                req.session.userData = response.data;
                res.send(response.data);
            })
            .catch((error) => {
                // Handle any errors here
                console.error('Request failed:', error);
                res.status(error.response ? error.response.status : 500).send(error.message);
            });
          }
          else{
            res.send(response.data)
          }
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
        "refresh_token":"1000.632e06eb56b23a1e025aa3be6d6aee64.19fba570d04a1144edb0e33da9f05794",
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
      const apiUrl = 'https://crmsandbox.zoho.eu/crm/v3/Contacts/628272000000399701/Deals';
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
  if(req.session.userData){
    console.log(true)
    return res.json({valid : true,userData:req.session.userData})
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
  app.get("/api/application",async(req,res)=>{
   if(!token || await isTokenExpired(token)){
      token = await refreshAccessToken();
      }
        const apiUrl = 'https://crmsandbox.zoho.eu/crm/v3/Contacts/627064000000397433';
        const _headers = {
        'Authorization': `Zoho-oauthtoken ${token}`
        };
        console.log("_headers",_headers) 
        const params = {
        fields: 'Full_Name,Account_Name,Email,Phone,Owner',
        };

        axios.get(apiUrl,{params: params, headers:_headers })
        .then((response) => {
            console.log(response)
            // Handle the successful response here
            const apiUrl = 'https://crmsandbox.zoho.eu/crm/v3/Contacts/627064000000397433/Deals';
            const _headers = {
            'Authorization': `Zoho-oauthtoken ${token}`
            };
            const params = {
            fields: 'Full_Name,Country,Course_Duration,Account_Name,Email,Stage,Contact_Name,Stage,Course,Preferred_University_Universities,Closing_Date,Course_Opted,Level1,Duration1,University1,University,Select_Program,Preferred_intake,Last_Qualification,English_Language_Certificate_IF_ANY,IELTS_PTE_score,Disability_or_Impairment,If_Yes_please_provide_details,How_did_you_hear_about_TEMC,Were_you_introduced_to_TEMC_by_and_Agent_or_a_Coun,JOB_Experience,Acknowledgement,If_YES_Insert_the_AGENT_IDENTIFICATION,Offer_Letter_Counsellor,Offer_Letter_Student,Terms_and_conditions,Please_upload_photo_identification_of_yourself,Privacy_Policy,Academic_Transcript,Upload_English,Electronic_signature,Date,Course_Level1,Course_Status',
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

        async function refreshAccessToken() {
          const api_Url = "https://accounts.zoho.eu/oauth/v2/token";
          const request_Body={
            'client_id': "1000.6GP4EGM1XX8TL9LUMCAD3HPPHPKJEG",
            'client_secret': "d1815120780298b7328c8b49b1ab6b1e6c3fbb4cc7",
            "refresh_token":"1000.632e06eb56b23a1e025aa3be6d6aee64.19fba570d04a1144edb0e33da9f05794",
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
          const apiUrl = 'https://crmsandbox.zoho.eu/crm/v3/Contacts/627064000000397433/Deals';
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

app.get("/api/getAgentStudentApp",async(req,res)=>{
  if(!token){
      token = await refreshAccessToken();
      console.log("token1",token) // Use await with async function.
      }
    else if (await isTokenExpired(token)) {
      // If the token is expired, refresh it or handle accordingly
      token = await refreshAccessToken();
      console.log("token2",token) 
      // Use await with async function.
    }
        const apiUrl = 'https://www.zohoapis.eu/crm/v3/Vendors/469374000004680022/Assigned_Students';
        const _headers = {
        'Authorization': `Zoho-oauthtoken ${token}`
        };
        console.log("_headers",_headers) 
        const params = {
        fields: 'Full_Name,Account_Name,Email,Phone'
        };

        axios.get(apiUrl,{params: params, headers:_headers })
        .then((response) => {
              res.send(response.data);
            }).catch((error) => {
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

// university api
app.get("/api/University-list",async(req,res)=>{
  if(!token){
      token = await refreshAccessToken();
      console.log("token1",token) // Use await with async function.
      }
    else if (await isTokenExpired(token)) {
      // If the token is expired, refresh it or handle accordingly
      token = await refreshAccessToken();
      console.log("token2",token) 
    }
        const apiUrl = 'https://www.zohoapis.eu/crm/v3/University';
        const _headers = {
        'Authorization': `Zoho-oauthtoken ${token}`
        };
        console.log("_headers",_headers)
        const params = {
        fields: 'Name,Owner,creatorID,Country,Modified_Time,Requirement,University_Description,English_Requirement'
        };     
        axios.get(apiUrl,{params: params, headers:_headers })
        .then((response) => {
              res.send(response.data);
            }).catch((error) => {
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

// Courses Filter API
app.get("/api/filtersCourses",async(req,res)=>{
  if(!token){
    token = await refreshAccessToken();
    console.log("token1",token) // Use await with async function.
    }
  else if (await isTokenExpired(token)) {
    // If the token is expired, refresh it or handle accordingly
    token = await refreshAccessToken();
    console.log("token2",token) 
    // Use await with async function.
  }
  const apiUrl = 'https://www.zohoapis.eu/crm/v3/University';
  const _headers = {
  'Authorization': `Zoho-oauthtoken ${token}`
  };
  console.log("_headers",_headers) 
  const params = {
  fields: 'Name,Owner,creatorID,Country,Modified_Time,Requirement,University_Description,English_Requirement'
  };
  axios.get(apiUrl,{params: params, headers:_headers })
  .then((response) => {
      const data=response.data.id
      const apiUrl = 'https://www.zohoapis.eu/crm/v3/Course';
        const _headers = {
        'Authorization': `Zoho-oauthtoken ${token}`
        };
        console.log("_headers",_headers) 
        const params = {
        fields: 'Name,Course_URL,University,Duration,Department,Educational_Qualification,Creator_ID,Course_Fee,Course_Level,Country,Course_Description,Course_level,Requirement',
        criteria:`(University.id:equals:${data})`
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
     }).catch((error) => {
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

// create application
app.post("/api/createapplication",async(req,res)=>{
  console.log("bodyvalue :",req.body)
  if(!token || await isTokenExpired(token)){
    console.log(1)
    token = await refreshAccessToken();
    }
  const apiUrl = 'https://www.zohoapis.eu/crm/v3/Potentials';
  const _headers = {
  'Authorization': `Zoho-oauthtoken ${token}`
  };
  console.log("_headers",_headers) 
  const request_Body={
    "data": [
        {
          "Deal_Name": req.body.Deal_Name,
          "Offer_Letter_Counsellor": [req.body.Offer_Letter_Counsellor],
          "Electronic_signature": req.body.Electronic_signature,
          "Country": req.body.Country,
          "Edit_Enabled":req.body.Edit_Enabled,
          "Select_Program": {
              "name": req.body.Select_Program["name"],
              "id": req.body.Select_Program["id"]
          },
          "Acknowledgement": req.body.Acknowledgement,
          "Course_Status": req.body.Course_Status,
          "Course_Duration": req.body.Course_Duration,
          "Terms_and_conditions": req.body.Terms_and_conditions,
          "Course_Level1":req.body.Course_Level1,
          "Stage": "APPLICATION SUBMITTED",
          "Upload_English": [req.body.Upload_English[0]],
          "Disability_or_Impairment": req.body.Disability_or_Impairment,
          "If_Yes_please_provide_details":req.body.If_YES_Insert_the_AGENT_IDENTIFICATION,
          "Privacy_Policy": req.body.Privacy_Policy,
          "English_Language_Certificate_IF_ANY": req.body.English_Language_Certificate_IF_ANY,
          "Academic_Transcript": [req.body.Academic_Transcript[0]],
          "IELTS_PTE_score": req.body.IELTS_PTE_score,
          "How_did_you_hear_about_TEMC": [req.body.How_did_you_hear_about_TEMC[0]],
          "Last_Qualification":req.body.Last_Qualification,
          "Date": req.body.date,
          "If_YES_Insert_the_AGENT_IDENTIFICATION":req.body.If_YES_Insert_the_AGENT_IDENTIFICATION,
          "Preferred_intake": [
              req.body.Preferred_intake[0]
          ],
          "Pipeline":"Applications",
          "University": req.body.University,
          "Please_upload_photo_identification_of_yourself": [req.body.Please_upload_photo_identification_of_yourself[0]],
          "Offer_Letter_Student": [req.body.Offer_Letter_Student[0]],
          "Were_you_introduced_to_TEMC_by_and_Agent_or_a_Coun": req.body.Were_you_introduced_to_TEMC_by_and_Agent_or_a_Coun,
          "Important_Dates": req.body.Important_Dates
      }
    ]
  };
  axios.post(apiUrl,request_Body,{headers: _headers})
  .then((response) => {
    console.log(req)
    res.send(response.data);  
     }).catch((error) => {
        // Handle any errors here
        console.error('Request failed:', error);
        res.status(error.response ? error.response.status : 500).send(error.message);
    });
  async function refreshAccessToken() {
    console.log(2)
    const api_Url = "https://accounts.zoho.eu/oauth/v2/token";
    const request_Body={
      'client_id': "1000.6GP4EGM1XX8TL9LUMCAD3HPPHPKJEG",
      'client_secret': "d1815120780298b7328c8b49b1ab6b1e6c3fbb4cc7",
      "refresh_token":"1000.632e06eb56b23a1e025aa3be6d6aee64.19fba570d04a1144edb0e33da9f05794",
      "grant_type":"refresh_token"
    };
    const headers ={
      'Content-Type': 'application/x-www-form-urlencoded',
    }
    try {
      const response = await axios.post(api_Url, request_Body,{headers: headers});
      console.log("_response", response.data);
      return response.data["access_token"];
    } catch (error) {
      // Handle any errors here
      console.error('Request failed:', error);
      throw error;
    }
  }

  async function isTokenExpired(token) {
    console.log(3)
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

app.listen(port,() => {
    console.log(`app listening on port ${port}`)
  })