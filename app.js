require('dotenv').config()
const express=require('express')
const app=express()
const pool=require('./db')
const bcrypt=require('bcrypt')
const cors=require('cors')
const jwt=require('jsonwebtoken')


app.use(cors());

const verifyJwt=(req,res,next)=>{
    const token=req.headers["x-access-token"];

    if(!token){
        console.log('no token present')
        res.send('no token is there')
    }else{
        jwt.verify(token,"jwtsecret",(err,decoded)=>{
            if(err){
                console.log('error not verified')
                return res.json({auth:false,message:'authorization failed'})
            }else{
                console.log('success verification');
                req.userId=decoded.id;
                req.sessionId=decoded.sessionId;
                req.role=decoded.role
                req.loginTime=decoded.iat
               console.log(decoded)
                console.log(req.userId,'all set indeed')
                next();
            }
        })
    }

}
function diff_minutes(dt1, dt2) 
 { 
  console.log(dt1-dt2)
  var diff =(dt2 - dt1.getTime()) / 1000;
  diff /= 60;
  console.log(diff)
  return Math.abs(Math.round(diff));
  
 }

app.use(express.json())
app.use(express.urlencoded({extended:true}))
app.get('/isAuth',verifyJwt,async(req,res,next)=>{
    try{console.log(process.env.BUCKET_STORAGE_URL)
        const token=req.headers['x-access-token'];
    const id=req.userId
    const role=req.role
    console.log(id,role);
  


           const result=await pool.query('SELECT * FROM users WHERE id=$1',[id])
           if(result.rowCount>0){
 
             res.json({auth:true,message:'you are authenticated',id,token,role})
           }else{
            res.json({auth:false,message:'not authorised yet',role})
 
        }
        
    

    }catch(e){
        console.log('not aouthorised');
    }
})

app.post('/login',async (req,res)=>{
    try{
        const {username,password}=req.body
        console.log(req.body)
        const user= await pool.query('SELECT * FROM users WHERE username=$1',[username])
        console.log(user.rows)
        if(user.rowCount===1){
            console.log(user.rows[0].password)
            const compPass= await bcrypt.compare(password,user.rows[0].password)
            if(compPass){
                if(username==='admin'){
                    const id=user.rows[0].id
                    const role=1
                    const token= jwt.sign({id,role},'jwtsecret',{
                        expiresIn:280,
                    })
             return   res.status(200).json({token:token,role})

                }
              
               
                const date=new Date()
                const id=user.rows[0].id
             const sessionTable=await pool.query('INSERT INTO user_session (login_time,user_id) VALUES($1,$2) RETURNING *',[date.toISOString(),id]);
             const role=0
             const sessionId=sessionTable.rows[0].session_id
             const token= jwt.sign({id,role,sessionId},'jwtsecret',{
                 expiresIn:280,
             })
             return   res.status(200).json({token:token,role})

            }else{
                console.log(compPass,'what password')
                throw new Error('User does not exist OR Password is wrong')
            }
        }else{
            throw new Error('User does not exist OR Password is wrong')

        }
    }catch(e){
        console.log('no user here',e)
        res.status(400).json({message:e.message})
    }
})

app.post('/registeruser',async(req,res)=>{
    try{
        console.log(req.body)
        const {username,password,email,mobile}=req.body;
        console.log(password,username)
        const user=await pool.query('SELECT * FROM users WHERE username=$1',[username]);
        const useremail= await pool.query('SELECT * FROM users WHERE email=$1',[email])
        console.log(user)
        if(user.rowCount>0){
           throw new Error('Person with this username already exist') 
        }
        if(useremail.rowCount>0){
            throw new Error('person with this email already exist')
        }
        else{
            console.log('where')
         const hashPassword=await bcrypt.hash(password,10);
         const NewUser=await pool.query('INSERT INTO users(username,email,password,mobile_number) VALUES($1,$2,$3,$4) RETURNING *',
         [username,email,hashPassword,mobile]);
         
         const id= NewUser.rows[0].id

         console.log(id)
         const date=new Date()

         const sessionTable=await pool.query('INSERT INTO user_session (login_time,user_id) VALUES($1,$2) RETURNING *',[date.toISOString(),id]);
         console.log(sessionTable.rows)
         const sessionId=sessionTable.rows[0].session_id
         
         const role=0
         const token= jwt.sign({id,role,sessionId},'jwtsecret',{
            expiresIn:280,
        })
         res.status(200).json({token:token,role})
       }
    }catch(err){
        console.log(err)
    res.status(400).json({message:err.message,auth:false })
    }
})

app.post('/logoutHandler',verifyJwt,async(req,res)=>{
   try{  
    const sessionId=req.sessionId
     const userId=req.userId
     const logoutDate=req.body.date
    //  console.log(logoutDate)
     const data=await pool.query('select * from user_session where session_id=$1',[sessionId])
     if(data.rowCount>0){
        const loginDate=data.rows[0].login_time
        const loginTime=new Date(loginDate)

        // console.log(loginDate)
        const sessionTime=diff_minutes(loginTime,logoutDate)
        console.log(sessionTime,'say whattttt')
        const updateTable=await pool.query('UPDATE user_session set session_time=$1 where session_id=$2',[sessionTime,sessionId])
        return res.json({updated:true})

     }
    }catch(e){
        console.log(e)
    }
})


















app.listen(4000,()=>{
    console.log('listening at 4000')
})