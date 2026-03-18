var express = require("express");
var router = express.Router();
let userController = require('../controllers/users')
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
let fs = require('fs');
const { CheckLogin } = require("../utils/authHandler");

const privateKey = fs.readFileSync('private.key', 'utf8');
const publicKey = fs.readFileSync('public.key', 'utf8');

router.post('/register', async function (req, res, next) {
    try {
        let { username, password, email } = req.body;
        let newUser = await userController.CreateAnUser(
            username, password, email, "69b0ddec842e41e8160132b8"
        )
        res.send(newUser)
    } catch (error) {
        res.status(404).send(error.message)
    }

})
router.post('/login', async function (req, res, next) {
    try {
        let { username, password } = req.body;
        let user = await userController.GetAnUserByUsername(username);
        if (!user) {
            res.status(404).send({
                message: "thong tin dang nhap sai"
            })
            return;
        }
        if (user.lockTime > Date.now()) {
            res.status(404).send({
                message: "ban dang bi ban"
            })
            return
        }
        if (bcrypt.compareSync(password, user.password)) {
            loginCount = 0;
            await user.save()
            let token = jwt.sign(
                { id: user._id },
                privateKey,
                {
                    algorithm: 'RS256',
                    expiresIn: '1h'
                }
            );
            res.send(token)
        } else {
            user.loginCount++;
            if (user.loginCount == 3) {
                user.loginCount = 0;
                user.lockTime = Date.now() + 3600 * 1000
            }
            await user.save()
            res.status(404).send({
                message: "thong tin dang nhap sai"
            })
        }
    } catch (error) {
        res.status(404).send({
            message: error.message
        })
    }

})
router.get('/me', CheckLogin, function (req, res, next) {
    res.send(req.user)
})
router.put('/change-password', CheckLogin, async function (req, res) {
    try {
        let { oldPassword, newPassword } = req.body;

        // 1. Validate input
        if (!oldPassword || !newPassword) {
            return res.status(400).send({
                message: "thieu oldPassword hoac newPassword"
            });
        }

        let user = req.user;

        // 2. Check old password
        let isMatch = bcrypt.compareSync(oldPassword, user.password);
        if (!isMatch) {
            return res.status(400).send({
                message: "mat khau cu khong dung"
            });
        }

        // 3. Validate new password
        let validateMsg = validateNewPassword(newPassword);
        if (validateMsg !== true) {
            return res.status(400).send({
                message: validateMsg
            });
        }

        // 4. Không cho trùng mật khẩu cũ
        if (bcrypt.compareSync(newPassword, user.password)) {
            return res.status(400).send({
                message: "mat khau moi khong duoc trung mat khau cu"
            });
        }

        // 5. Update password
        user.password = newPassword;
        await user.save(); // sẽ tự hash ở schema

        res.send({
            message: "doi mat khau thanh cong"
        });

    } catch (error) {
        res.status(500).send({
            message: error.message
        });
    }
});
function validateNewPassword(password) {
    if (password.length < 6) {
        return "mat khau phai >= 6 ky tu";
    }

    if (!/[A-Z]/.test(password)) {
        return "phai co it nhat 1 chu hoa";
    }

    if (!/[0-9]/.test(password)) {
        return "phai co it nhat 1 so";
    }

    return true;
}

module.exports = router;