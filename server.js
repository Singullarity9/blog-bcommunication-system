import express from 'express'
import mongoose from 'mongoose'
import 'dotenv/config'
import bcrypt from 'bcrypt'
import { nanoid } from 'nanoid'
import jwt from 'jsonwebtoken'
import User from './Schema/User.js'
import cors from 'cors'
import multer from 'multer'
import bodyParser from 'body-parser'
import path, { dirname } from 'path'
import { fileURLToPath } from 'url'
import Notification from './Schema/Notification.js'
import Blog from './Schema/Blog.js'
import Comment from './Schema/Comment.js'

const server = express()
const PORT = 3000
const __dirname = dirname(fileURLToPath(import.meta.url))

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; //邮箱校验规则
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; //密码校验规则

let upload = multer({ dest: './public/uploads/' })

server.use(express.json())
server.use(cors())
server.use(bodyParser.json())
server.use(bodyParser.urlencoded({ extended: true }))
server.use(express.static(path.join(__dirname, 'public')))

mongoose.connect(process.env.DB_LOCATION, {
    autoIndex: true
})

//jwt验证中间件
const verifyJWT = (req, res, next) => {
    const Header = req.headers['authorization']
    const token = Header && Header.split(' ')[1]

    if (!token) {
        return res.status(401).json({ error: '无权限访问' })
    }

    jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, user) => {
        if (err)
            return res.status(403).json({ error: "token不合法" })

        req.user = user.id
        next()
    })
}

const formatUserData = (user) => {
    const token = jwt.sign({ id: user._id }, process.env.SECRET_ACCESS_KEY)

    return {
        token,
        profile_img: user.personal_info.profile_img,
        username: user.personal_info.username,
        fullname: user.personal_info.fullname
    }
}

const generateUsername = async (email) => {
    let username = email.split('@')[0]

    let isUsernameNotUnique = await User.exists({ "personal_info.username": username }).then(result => result)

    isUsernameNotUnique ? username += nanoid().substring(0, 5) : ""

    return username
}

//注册
server.post('/signup', (req, res) => {
    let { fullname, email, password } = req.body

    if (fullname?.length < 2)
        return res.status(403).json({ "error": "用户名长度至少为2" })
    if (!email?.length)
        return res.status(403).json({ "error": "邮箱名不能为空" })
    if (!emailRegex.test(email))
        return res.status(403).json({ "error": "邮箱格式不正确" })
    if (!passwordRegex.test(password))
        return res.status(403).json({ "error": "密码长度应为6-20位,包括数字和大小写字母" })

    bcrypt.hash(password, 10, async (err, hash_password) => {
        let username = await generateUsername(email)

        let user = new User({
            personal_info: { fullname, email, password: hash_password, username }
        })

        user.save().then(u => {
            return res.status(200).json(formatUserData(u))
        })
            .catch(err => {
                if (err.code === 11000)
                    return res.status(500).json({ "error": "该邮箱已用于注册" })

                return res.status(500).json({ "error": err.message })
            })
    })
})

//登录
server.post('/signin', (req, res) => {
    let { email, password } = req.body

    User.findOne({ "personal_info.email": email })
        .then(user => {
            if (!user)
                return res.status(403).json({ "error": "该邮箱未注册" })
            bcrypt.compare(password, user.personal_info.password, (err, result) => {
                if (err)
                    return res.status(403).json({ "error": "登录失败,请重新尝试" })

                if (!result)
                    return res.status(403).json({ "error": "密码不正确" })
                else
                    return res.status(200).json(formatUserData(user))
            })
        })
        .catch(err => {
            return res.status(500).json({ "error": err.message })
        })
})

//图片上传
server.post("/upload", upload.single('banner'), function (req, res) {
    res.send(req.file);
})

//文章发布
server.post('/createBlog', verifyJWT, (req, res) => {
    let authorId = req.user
    let { title, des, banner, tags, content, draft, id } = req.body
    console.log(req.body);

    if (!title.length)
        return res.status(403).json({ error: '未提供博客标题' })

    if (!draft) {
        if (!des.length || des.length > 200)
            return res.status(403).json({ error: '需提供博客描述信息,且内容不能超过200字' })

        if (!banner.length)
            return res.status(403).json({ error: '未提供博客banner' })

        if (!content.blocks.length)
            return res.status(403).json({ error: '未提供博客正文内容' })

        if (!tags.length || tags.length > 10)
            return res.status(403).json({ error: '需提供博客标签,且个数不能超过10个' })
    }

    tags = tags.map(tag => tag.toLowerCase())

    let blog_id = id || nanoid()

    if (id) {


        Blog.findOneAndUpdate({ blog_id }, { title, des, banner, content, tags, draft: draft ? draft : false })
            .then(() => {
                return res.status(200).json({ id: blog_id })
            })
            .catch(err => {
                return res.status(500).json({ error: '更新博客信息失败' })
            })
    } else {
        let blog = new Blog({ title, des, banner, tags, content, author: authorId, blog_id, draft: Boolean(draft) })

        blog.save()
            .then(blog => {
                let incrementVal = draft ? 0 : 1

                User.findOneAndUpdate({ _id: authorId },
                    {
                        $inc: { "account_info.total_posts": incrementVal },
                        $push: { "blogs": blog._id }
                    })
                    .then(user => {
                        return res.status(200).json({ id: blog.blog_id })
                    })
                    .catch(err => {
                        return res.status(500).json({ error: '更新博客发布个数失败' })
                    })
            })
            .catch(err => {
                return res.status(500).json({ error: err.message })
            })
    }
})

//获取最新博客数据
server.post('/latestBlog', (req, res) => {
    let { page } = req.body
    let maxLimit = 5

    Blog.find({ draft: false })
        .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
        .sort({ "publishedAt": -1 })
        .select("blog_id title des banner activity tags publishedAt -_id")
        .skip(((page - 1) * maxLimit))
        .limit(maxLimit)
        .then(blogs => {
            return res.status(200).json({ blogs })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post('/all-latest-blogs-count', (req, res) => {
    Blog.countDocuments({ draft: false })
        .then(count => {
            return res.status(200).json({ totalDocs: count })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

//获取热度最高的博客数据
server.get('/trendingBlog', (req, res) => {
    let maxLimit = 5

    Blog.find({ draft: false })
        .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
        .sort({ "publishedAt": -1 })
        .select("blog_id title des banner activity tags publishedAt -_id")
        .limit(maxLimit)
        .then(blogs => {
            return res.status(200).json({ blogs })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post('/searchBlogs', (req, res) => {
    let { tag, query, author, page, limit, eliminate_blog } = req.body

    let findQuery
    if (tag) {
        findQuery = { tags: tag, draft: false, blog_id: { $ne: eliminate_blog } }
    } else if (query) {
        findQuery = { draft: false, title: new RegExp(query, 'i') }
    } else if (author) {
        findQuery = { author, draft: false }
    }

    let maxLimit = limit ? limit : 5

    Blog.find(findQuery)
        .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
        .sort({ "publishedAt": -1 })
        .select("blog_id title des banner activity tags publishedAt -_id")
        .skip((page - 1) * maxLimit)
        .limit(maxLimit)
        .then(blogs => {
            return res.status(200).json({ blogs })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post('/search-blogs-count', (req, res) => {
    let { tag, author, query } = req.body

    let findQuery
    if (tag) {
        findQuery = { tags: tag, draft: false }
    } else if (query) {
        findQuery = { draft: false, title: new RegExp(query, 'i') }
    } else if (author) {
        findQuery = { author, draft: false }
    }

    Blog.countDocuments(findQuery)
        .then(count => {
            return res.status(200).json({ totalDocs: count })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post('/searchUsers', (req, res) => {
    let { query } = req.body

    User.find({ "personal_info.fullname": new RegExp(query, 'i') })
        .limit(50)
        .select("personal_info.fullname personal_info.username personal_info.profile_img -_id")
        .then(users => {
            return res.status(200).json({ users })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post('/getProfile', (req, res) => {
    let { username } = req.body

    User.findOne({ 'personal_info.username': username })
        .select('-personal_info.password -google_auth -updatedAt -blogs')
        .then(user => {
            res.status(200).json({ user })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post('/getBlog', (req, res) => {
    let { blog_id, draft, mode } = req.body

    let incrementVal = mode !== 'edit' ? 1 : 0

    Blog.findOneAndUpdate({ blog_id }, { $inc: { "activity.total_reads": incrementVal } })
        .populate("author", "personal_info.fullname personal_info.username personal_info.profile_img")
        .select("title des content banner activity publishedAt blog_id tags")
        .then(blog => {
            User.findOneAndUpdate({ "personal_info.username": blog.author.personal_info.username }, {
                $inc: { 'account_info.total_reads': incrementVal }
            })
                .catch(err => {
                    return res.status(500).json({ error: err.message })
                })

            if (blog.draft && !draft) {
                return res.status(500).json({ error: '无权限使用编辑功能' })
            }

            return res.status(200).json({ blog })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

//点赞功能接口
server.post('/likeBlog', verifyJWT, (req, res) => {
    let user_id = req.user

    let { _id, isLikedByUser } = req.body

    let incrementVal = !isLikedByUser ? 1 : -1

    Blog.findOneAndUpdate({ _id }, { $inc: { "activity.total_likes": incrementVal } })
        .then(blog => {
            if (!isLikedByUser) {
                let like = new Notification({
                    type: 'like',
                    blog: _id,
                    notification_for: blog.author,
                    user: user_id
                })

                like.save()
                    .then(notification => {
                        return res.status(200).json({ liked_by_user: true })
                    })
                    .catch(err => {
                        return res.status(500).json({ error: err.message })
                    })

            } else {
                Notification.findOneAndDelete({ user: user_id, blog: _id, type: 'like' })
                    .then(data => {
                        return res.status(200).json({ liked_by_user: false })
                    })
                    .catch(err => {
                        return res.status(500).json({ error: err.message })
                    })
            }
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post('/isLiked-by-user', verifyJWT, (req, res) => {
    let user_id = req.user

    let { _id } = req.body

    Notification.exists({ user: user_id, type: 'like', blog: _id })
        .then(result => {
            return res.status(200).json({ result })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

//发布评论接口
server.post('/addComment', verifyJWT, (req, res) => {
    let user_id = req.user

    let { _id, comment, blog_author, replying_to, notification_id } = req.body

    if (!comment.length) {
        return res.status(403).json({ error: '评论内容为空' })
    }

    let commentObj = {
        blog_id: _id, blog_author, comment, commented_by: user_id
    }

    if (replying_to) {
        commentObj.parent = replying_to
        commentObj.isReply = true
    }

    new Comment(commentObj).save()
        .then(async commentFile => {

            let { comment, commentedAt, children } = commentFile
            //更新评论博客字段信息
            Blog.findOneAndUpdate({ _id },
                {
                    $push: { "comments": commentFile._id },
                    $inc: { "activity.total_comments": 1, "activity.total_parent_comments": replying_to ? 0 : 1 },
                })
                .then(blog => {
                    console.log('新建评论成功');
                })
                .catch(err => {
                    return res.status(500).json({ error: err.message })
                })

            let notificationObj = {
                type: replying_to ? 'reply' : 'comment',
                blog: _id,
                notification_for: blog_author,
                user: user_id,
                comment: commentFile._id
            }

            if (replying_to) {
                notificationObj.replied_on_comment = replying_to

                await Comment.findOneAndUpdate({ _id: replying_to }, { $push: { children: commentFile._id } })
                    .then(reply => {
                        notificationObj.notification_for = reply.commented_by
                    })

                if (notification_id) {
                    Notification.findOneAndUpdate({ _id: notification_id }, { reply: commentFile._id })
                        .then(notification => {
                            console.log('通知信息更新');
                        })
                }
            }

            new Notification(notificationObj).save()
                .then(notification => console.log('评论通知创建成功'))
                .catch(err => {
                    return res.status(500).json({ error: err.message })
                })

            return res.status(200).json({
                comment, commentedAt, _id: commentFile._id, user_id, children
            })
        })

})

//获取某条博客所有评论信息
server.post('/get-blog-comments', (req, res) => {
    let { blog_id, skip } = req.body

    let maxLimit = 5

    Comment.find({ blog_id, isReply: false })
        .populate("commented_by", "personal_info.username personal_info.fullname personal_info.profile_img")
        .skip(skip)
        .limit(maxLimit)
        .sort({
            'commentedAt': -1
        })
        .then(comment => {
            return res.status(200).json(comment)
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

//获取单个评论子评论信息
server.post('/getReplies', (req, res) => {
    let { _id, skip } = req.body

    let maxLimit = 5

    Comment.findOne({ _id })
        .populate({
            path: 'children',
            options: {
                limit: maxLimit,
                skip: skip,
                sort: { 'commentedAt': -1 }
            },
            populate: {
                path: 'commented_by',
                select: "personal_info.profile_img personal_info.username personal_info.fullname"
            },
            select: "-blog_id -updatedAt"
        })
        .select('children')
        .then(doc => {
            return res.status(200).json({ replies: doc.children })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

const deleteComment = (_id) => {
    Comment.findOneAndDelete({ _id })
        .then(comment => {
            if (comment.parent) {
                Comment.findOneAndUpdate({ _id: comment.parent }, { $pull: { children: _id } }).
                    then((data) => {
                        console.log('更新评论信息成功');
                    })
                    .catch(err => {
                        console.log(err);
                    })
            }

            Notification.findOneAndDelete({ comment: _id }).then(notification => console.log('删除评论相关通知信息成功', notification))

            Notification.findOneAndUpdate({ reply: _id }, { $unset: { reply: 1 } }).then(notification => console.log('更新回复相关通知信息成功', notification))

            Blog.findOneAndUpdate({ _id: comment.blog_id }, {
                $pull: { comments: _id }, $inc: {
                    "activity.total_comments": -1,
                    "activity.total_parent_comments": comment.parent ? 0 : -1
                }
            })
                .then(blog => {
                    if (comment.children.length) {
                        comment.children.map(replies => {
                            deleteComment(replies)
                        })
                    }
                })
        })
        .catch(err => {
            console.log(err.message);
        })
}

//删除评论
server.post('/deleteComment', verifyJWT, (req, res) => {
    let user_id = req.user

    let { _id } = req.body

    Comment.findOne({ _id })
        .then(comment => {
            if (user_id == comment.commented_by || user_id == comment.blog_author) {
                deleteComment(_id)

                return res.status(200).json({ status: 'done' })
            } else {
                return res.status(403).json({ error: '无权限删除该评论' })
            }
        })
})

//修改用户密码
server.post('/changePassword', verifyJWT, (req, res) => {
    let { currentPassword, newPassword } = req.body

    if (!passwordRegex.test(currentPassword) || !passwordRegex.test(newPassword)) {
        return res.status(403).json({ error: '密码格式不正确,密码长度应为6-20位,包括数字和大小写字母' })
    }

    User.findOne({ _id: req.user })
        .then(user => {
            bcrypt.compare(currentPassword, user.personal_info.password, (err, result) => {
                if (err) {
                    return res.status(500).json({ error: "服务器端出错" })
                }

                if (!result) {
                    return res.status(403).json({ error: '密码输入错误' })
                }

                bcrypt.hash(newPassword, 10, (err, hash_password) => {
                    User.findOneAndUpdate({ _id: req.user }, { "personal_info.password": hash_password })
                        .then(u => {
                            return res.status(200).json({ status: '密码更新成功' })
                        })
                        .catch(err => {
                            return res.status(500).json({ error: err.message })
                        })
                })
            })
        })
        .catch(err => {
            res.status(500).json({ error: '用户不存在' })
        })
})

//更新用户头像
server.post('/update-profile-img', verifyJWT, (req, res) => {
    let { url } = req.body

    User.findOneAndUpdate({ _id: req.user }, { 'personal_info.profile_img': url })
        .then(() => {
            return res.status(200).json({ profile_img: url })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

//更新用户个人信息
server.post('/updateProfile', verifyJWT, (req, res) => {
    let { bio } = req.body

    let bioLimit = 150
    if (bio.length > bioLimit) {
        return res.status(403).json({ error: '个人介绍内容长度超出' })
    }

    User.findOneAndUpdate({ _id: req.user }, { 'personal_info.bio': bio })
        .then(() => {
            res.status(200).json({ status: '更新成功' })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

//请求新通知
server.get('/newNotification', verifyJWT, (req, res) => {
    let user_id = req.user

    Notification.exists({ notification_for: user_id, seen: false, user: { $ne: user_id } })
        .then(result => {
            if (result) {
                return res.status(200).json({ new_notification_available: true })
            } else {
                return res.status(200).json({ new_notification_available: false })
            }
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

//获取通知具体信息
server.post('/notifications', verifyJWT, (req, res) => {
    let user_id = req.user

    let { page, filter, deletedDocCount } = req.body

    let maxLimit = 10

    let findQuery = { notification_for: user_id, user: { $ne: user_id } }

    let skipDocs = (page - 1) * maxLimit

    if (filter !== 'all') {
        findQuery.type = filter
    }

    if (deletedDocCount) {
        skipDocs -= deletedDocCount
    }

    Notification.find(findQuery)
        .skip(skipDocs)
        .limit(maxLimit)
        .populate('blog', 'title blog_id')
        .populate('user', 'personal_info.fullname personal_info.username personal_info.profile_img')
        .populate('comment', 'comment')
        .populate('replied_on_comment', 'comment')
        .populate('reply', 'comment')
        .sort({ createdAt: -1 })
        .select("createdAt type seen reply")
        .then(notifications => {
            Notification.updateMany(findQuery, { seen: true })
                .skip(skipDocs)
                .limit(maxLimit)
                .then(() => {
                    console.log('通知已查看');
                })

            return res.status(200).json({ notifications })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

//获取通知总数
server.post('/all-notifications-count', verifyJWT, (req, res) => {
    let user_id = req.user

    let { filter } = req.body

    let findQuery = { notification_for: user_id, user: { $ne: user_id } }

    if (filter !== 'all') {
        findQuery.type = filter
    }

    Notification.countDocuments(findQuery)
        .then(count => {
            return res.status(200).json({ totalDocs: count })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post('/user-written-blogs', verifyJWT, (req, res) => {
    let user_id = req.user

    let { page, draft, query, deletedDocCount } = req.body

    let maxLimit = 5
    let skipDocs = (page - 1) * maxLimit

    if (deletedDocCount) {
        skipDocs -= deletedDocCount
    }

    let findQuery
    if (query) {
        findQuery = { draft, author: user_id, title: new RegExp(query, 'i') }
    } else {
        findQuery = { author: user_id, draft }
    }

    Blog.find(findQuery)
        .skip(skipDocs)
        .limit(maxLimit)
        .sort({ 'publishedAt': -1 })
        .select("title banner publishedAt blog_id activity des draft -_id")
        .then(blogs => {
            return res.status(200).json({ blogs })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post('/user-written-blogs-count', (req, res) => {
    let user_id = req.user

    let { draft, query } = req.body

    Blog.countDocuments({ author: user_id, draft, title: new RegExp(query, 'i') })
        .then(count => {
            res.status(200).json({ totalDocs: count })
        })
        .catch(err => {
            res.json(500).json({ error: err.message })
        })
})

//删除个人博客
server.post('/deleteBlog', verifyJWT, (req, res) => {
    let user_id = req.user
    let { blog_id } = req.body

    Blog.findOneAndDelete({ blog_id })
        .then(blog => {
            Notification.deleteMany({ blog: blog._id }).then(data => console.log('删除相关通知'))

            Comment.deleteMany({ blog: blog._id }).then(data => console.log('删除相关评论'))

            User.findOneAndUpdate({ _id: user_id }, { $pull: { blog: blog._id }, $inc: { "account_info.total_posts": -1 } })
                .then(user => console.log('博客已删除'))

            return res.status(200).json({ status: 'done' })
        })
        .catch(err => {
            res.json(500).json({ error: err.message })
        })
})

server.listen(PORT, () => {
    console.log(`server running at port ${PORT}`);
})