const mongoose = require("mongoose");
const mongoURI = "mongodb://127.0.0.1:27017/vishal"


const connectToMongo =async ()=>{
    // await mongoose.connect(mongoURI, function (err) {
    // if(err)console.log(err)
    // else{
    //     console.log("connected mongodb")
    // }        
    // })
    try {
        mongoose.set("strictQuery", false);
        mongoose.connect(mongoURI);
        console.log("Connected to Mongo Successfully!");
      } catch (error) {
        console.log(error);
      }
    
}

module.exports = connectToMongo;