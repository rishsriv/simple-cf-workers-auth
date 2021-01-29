//TODO: add support for login through other channels
// - Apple
// - Twitter
// - Google
// - Github

'use strict';
const crypto = require('crypto');

addEventListener('fetch', event => {
  const request = event.request;
  if (request.method === "OPTIONS") {
    //handle CORS
    event.respondWith(handleOptions(request));
  } else if(request.method === "POST") {
    // Handle requests for Auth
    event.respondWith(handleRequest(request));
  } else {
    event.respondWith(
      new Response(null, {status: 405, statusText: "Method Not Allowed"}),
    )
  }
})

/**
 * generates random string of characters i.e salt
 * @function
 * @param {number} length - Length of the random string.
 */
const genRandomString = function(length){
  return crypto.randomBytes(Math.ceil(length/2))
          .toString('hex') /** convert to hexadecimal format */
          .slice(0,length);   /** return required number of characters */
};

/**
 * hash password with sha256.
 * @function
 * @param {string} password - List of required fields.
 * @param {string} salt - Data to be validated.
 */
const sha256 = function(password, salt){
  let hash = crypto.createHmac('sha256', salt); /** Hashing algorithm sha256 */
  hash.update(password);
  const hashedPassword = hash.digest('hex');
  return hashedPassword;
};

/**
 * hash password with salt.
 * @function
 * @param {string} userPassword
 */
const saltHashPassword = function(userPassword) {
  const salt = genRandomString(16); /** Gives us salt of length 16 */
  const hashedPassword = sha256(userPassword, salt);
  return {salt: salt, hash: hashedPassword};
}

async function userExists(userEmail) {
  const userDets = await USERS.get(userEmail);
  if (userDets === null) {
    return false;
  } else {
    return true;
  }
}

//TODO: [low priority] also add an an optional expiry date to the user's credentials?
//For paid users, if the period for which they buy expires, they won't have access anymore
async function updateUser(userEmail, userPassword) {
  const passDets = saltHashPassword(userPassword);
  try {
    await USERS.put(userEmail, JSON.stringify(passDets));
    return {"success": true, "hash": passDets.hash};
  } catch(err) {
    return {"success": false, "message": "internal error"};
  }
}

async function addUser(userEmail, userPassword) {
  const thisUserExists = await userExists(userEmail);
  if (thisUserExists === false) {
    return await updateUser(userEmail, userPassword)
  } else {
    return {"success": false, "message": "Sorry! That username is taken."};
  }
}

async function isCorrectPassword(userEmail, userPassword) {
  try {
    const userDets = await USERS.get(userEmail, "json");
    const storedSalt = userDets.salt;
    const storedHash = userDets.hash;
    if (storedHash === sha256(userPassword, storedSalt)) {
      return {"success": true, "hash": storedHash};
    } else {
      return {"success": false, "message": "wrong password"};
    }
  } catch(err) { //handles cases if user does not exist
    return {"success": false, "message": "wrong password"};
  }
}

async function updatePassword(userEmail, oldPassword, newPassword) {
  const passCorrect = await isCorrectPassword(userEmail, oldPassword);
  if (passCorrect.success === true) {
    const changeAttempt = await updateUser(userEmail, newPassword);
    if (changeAttempt.success === true) {
      return {"success": true, "hash": changeAttempt.hash};
    } else {
      return {"success": false, "message": "internal error"};
    }
  } else {
    return {"success": false, "message": "old password is wrong"};
  }
}

async function sendForgotPasswordEmail(userEmail) {
  //TODO  
}

async function deleteUser(userEmail, userPassword) {
  try {
    const passCorrect = await isCorrectPassword(userEmail, userPassword);
    if (passCorrect.success === true) {
      await USERS.delete(userEmail);
      return {"success": true};
    } else {
      return {"success": false, "message": "wrong password"};
    }
  } catch(err) {
    return {"success": false, "message": "an internal error occurred"};
  }
}

/**
 * Respond with hello worker text
 * @param {Request} request
 */
async function handleRequest(request) {
  const requestDets = await request.json();
  
  //reqType is one of sign-up, login, updatePassword, forgotPassword, or deleteUser
  const { reqType, userEmail, userPass, oldPass } = requestDets;
  let dets;

  if (reqType === "signup") {
    dets = await addUser(userEmail, userPass);
  } else if (reqType === "login") {
    dets = await isCorrectPassword(userEmail, userPass);
  } else if (reqType === "updatePassword") {
    dets = await updatePassword(userEmail, oldPass, userPass);
  } else if (reqType === "forgotPassword") {

  } else if (reqType === "deleteUser") {
    dets = await deleteUser(userEmail, userPass);
  } else {
    return new Response("The server refuses the attempt to brew coffee with a teapot", {
      status: 418, headers: { 'content-type': 'text/plain', 'Access-Control-Allow-Origin': '*'}
    });
  }
  const resp = JSON.stringify(dets);
  return new Response(resp, {status: 200, headers: {'Content-Type': "application/json", 'Access-Control-Allow-Origin': '*'}});
}

async function handleOptions(request) {
  let headers = request.headers;
  if (
    headers.get("Origin") !== null &&
    headers.get("Access-Control-Request-Method") !== null &&
    headers.get("Access-Control-Request-Headers") !== null
  ) {
    let respHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": request.headers.get("Access-Control-Request-Headers"),
    }

    return new Response(null, {
      headers: respHeaders,
    })
  }
  else {
    return new Response(null, {
      headers: {
        "Allow": "POST, OPTIONS",
      },
    })
  }
}
