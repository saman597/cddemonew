const expressJWT = require('express-jwt');

const userController = require('../controllers/userController.js');
const authMiddleware = require('../middlewares/authMiddleware');

const router = require('express').Router();

router.route('/').get(expressJWT({secret: process.env.JWT_SECRET, requestProperty: 'auth', algorithms: ['sha1', 'RS256', 'HS256']}), authMiddleware.checkAuth, userController.getData);

router.route('/:userId').get(userController.getDataById);

router.route('/signup').post(userController.signUp);

router.route('/login').post(userController.login);

router.route('/forgotPassword').post(userController.forgotPwd);

router.route('/resetPassword').patch(userController.resetPwd);

module.exports = router;