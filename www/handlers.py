import re, time, json, logging, hashlib, base64, asyncio

from aiohttp import web

from webkj import get, post
from apis import APIValueError, APIResourceNotFoundError, APIError, APIPermissionError, Page
from models import User, Comment, Blog, next_id
from config import configs
import markdown2 

COOKIE_NAME = 'awesession'  # cookie名，用于设置cookie
_COOKIE_KEY = configs.session.secret  # cookie密钥，作为加密cookie的原始字符串的一部分

# 验证用户身份
# 如果没有用户或用户没有管理员属性，报错
def check_admin(request):
    if request.__user__ is None or not request.__user__.admin:
        raise APIPermissionError()


# 作用是获取页码
def get_page_index(page_str):
    # 将传入的字符转化为页码信息
    # 实际上就是对页码信息做合法化检查
    p = 1
    try:
        p = int(page_str)
    except ValueError as e:
        pass
    if p < 1:
        p = 1
    return p

def text2html(text):
    # 先用filter函数对输入的文本进行过滤处理，断行，去收尾空白字符
    # 再用map函数对特殊符号进行转换，在将字符串装入html的<p>标签中
    lines = map(lambda s: '<p>%s</p>' % s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'), filter(lambda s: s.strip() != '', text.split('\n')))
    # lines是一个字符串列表，该字符串即表示html的段落
    return ''.join(lines)


#api


#首页
@get('/')
@asyncio.coroutine
def index(*, page='1',request):
    page_index = get_page_index(page)
    num = yield from Blog.findNumber('count(id)')
    page = Page(num, page_index)
    if num == 0:
        blogs = []
    else:
        blogs = yield from Blog.findAll(orderBy='created_at desc', limit=(page.offset, page.limit))
    # 返回一个模板，指示使用何种模板，模板的内容
    # app.py的response_factory将会对handler.py的返回值进行分类处理
    return {
        '__template__': 'blogs.html',
        '__user__':request.__user__,
        'page': page,
        'blogs': blogs
    }

# 页面：博客详情页
@get('/blog/{id}')
@asyncio.coroutine
def get_blog(id, request):
    blog = yield from Blog.find(id)  # 通过id从数据库中拉去博客信息
    # 从数据库拉取指定blog的全部评论，按时间降序排序，即最新的排在最前
    comments = yield from Comment.findAll('blog_id=?', [id], orderBy='created_at desc')
    # 将每条评论都转化成html格式
    for c in comments:
        c.html_content = text2html(c.content)
    # blog也是markdown格式，将其转化成html格式
    blog.html_content = markdown2.markdown(blog.content)
    return {
        '__template__': 'blog.html',
        'blog': blog,
        '__user__':request.__user__,
        'comments': comments
    }






# API:用户注册

@get('/register')
def register():
    return {
        '__template__': 'register.html'
    }


_RE_EMAIL = re.compile(r'^[a-z0-9\.\-\_]+\@[a-z0-9\-\_]+(\.[a-z0-9\-\_]+){1,4}$')
_RE_SHA1 = re.compile(r'^[0-9a-f]{40}$')

@post('/api/users')
@asyncio.coroutine
def api_register_user(*, email, name, passwd):
    if not name or not name.strip():
        raise APIValueError('name')
    if not email or not _RE_EMAIL.match(email):
        raise APIValueError('email')
    if not passwd or not _RE_SHA1.match(passwd):
        raise APIValueError('passwd')
    users = yield from User.findAll('email=?', [email])
    if len(users) > 0:
        raise APIError('register:failed', 'email', 'Email is already in use.')
    uid = next_id()
    sha1_passwd = '%s:%s' % (uid, passwd)
    user = User(id=uid, name=name.strip(), email=email, passwd=hashlib.sha1(sha1_passwd.encode('utf-8')).hexdigest(), image='http://www.gravatar.com/avatar/%s?d=mm&s=120' % hashlib.md5(email.encode('utf-8')).hexdigest())
    yield from user.save()
    # make session cookie:
    r = web.Response()
    r.set_cookie(COOKIE_NAME, user2cookie(user, 86400), max_age=86400, httponly=True)
    user.passwd = '******'
    r.content_type = 'application/json'
    r.body = json.dumps(user, ensure_ascii=False).encode('utf-8')
    return r



# 登录
def user2cookie(user, max_age):
    '''
    Generate cookie str by user.
    '''
    # build cookie string by: id-expires-sha1
    expires = str(int(time.time() + max_age))
    s = '%s-%s-%s-%s' % (user.id, user.passwd, expires, _COOKIE_KEY)
    L = [user.id, expires, hashlib.sha1(s.encode('utf-8')).hexdigest()]
    return '-'.join(L)


@asyncio.coroutine
def cookie2user(cookie_str):
    '''
    Parse cookie and load user if cookie is valid.
    '''
    if not cookie_str:
        return None
    try:
        L = cookie_str.split('-')
        if len(L) != 3:
            return None
        uid, expires, sha1 = L
        if int(expires) < time.time():
            return None
        user = yield from User.find(uid)
        if user is None:
            return None
        s = '%s-%s-%s-%s' % (uid, user.passwd, expires, _COOKIE_KEY)
        if sha1 != hashlib.sha1(s.encode('utf-8')).hexdigest():
            logging.info('invalid sha1')
            return None
        user.passwd = '******'
        return user
    except Exception as e:
        logging.exception(e)
        return None


@get('/signin')
def signin():
    return {
        '__template__': 'signin.html'
    }



@post('/api/authenticate')
@asyncio.coroutine
def authenticate(*, email, passwd):
    if not email:
        raise APIValueError('email', 'Invalid email.')
    if not passwd:
        raise APIValueError('passwd', 'Invalid password.')
    users = yield from User.findAll('email=?', [email])
    if len(users) == 0:
        raise APIValueError('email', 'Email not exist.')
    user = users[0]
    # check passwd:
    sha1 = hashlib.sha1()
    sha1.update(user.id.encode('utf-8'))
    sha1.update(b':')
    sha1.update(passwd.encode('utf-8'))
    if user.passwd != sha1.hexdigest():
        raise APIValueError('passwd', 'Invalid password.')
    # authenticate ok, set cookie:
    r = web.Response()
    r.set_cookie(COOKIE_NAME, user2cookie(user, 86400), max_age=86400, httponly=True)
    user.passwd = '******'
    r.content_type = 'application/json'
    r.body = json.dumps(user, ensure_ascii=False).encode('utf-8')
    return r





@get('/signout')
def signout(request):
    referer = request.headers.get('Referer')
    r = web.HTTPFound(referer or '/')
    r.set_cookie(COOKIE_NAME, '-deleted-', max_age=0, httponly=True)
    logging.info('user signed out.')
    return r



#管理页

@get('/manage/blogs')
def manage_blogs(*, page='1'):
    return {
        '__template__': 'manage_blogs.html',
        'page_index': get_page_index(page)
    }
@get('/manage/blogs/create')
def manage_create_blog():
    return {
        '__template__': 'manage_blog_edit.html',
        'id': '',  # id的值将传给js变量I
        # action的值也将传给js变量action
        # 将在用户提交博客的时候，将数据post到action制定的路径，此处即为创建博客的api
        'action': '/api/blogs'
    }

# 管理重定向
@get('/manage/')
def manage():
    return 'redirect:/manage/comments'



# 页面：评论列表页
@get('/manage/comments')
def manage_comments(*, page='1'):
    return {
        '__template__': 'manage_comments.html',
        'page_index': get_page_index(page)
    }


# 页面：修改博客页
@get('/manage/blogs/edit')
def manage_edit_blog(*, id):
    return {
        '__template__': 'manage_blog_edit.html',
        'id': id,
        'action': '/api/blogs/%s' % id
    }


# 页面：用户管理
@get('/manage/users')
def manage_users(*, page='1'):  # 管理页面默认从1开始
    return {
        '__template__': 'manage_users.html',
        'page_index': get_page_index(page)  # 通过page_index来显示分页
    }






@post('/api/blogs')
@asyncio.coroutine
def api_create_blog(request, *, name, summary, content):
    check_admin(request) # 检查用户权限
    # 验证博客信息的合法性
    if not name or not name.strip():
        raise APIValueError('name', 'name cannot be empty.')
    if not summary or not summary.strip():
        raise APIValueError('summary', 'summary cannot be empty.')
    if not content or not content.strip():
        raise APIValueError('content', 'content cannot be empty.')
    # 创建博客对象
    blog = Blog(user_id=request.__user__.id, user_name=request.__user__.name, user_image=request.__user__.image, name=name.strip(), summary=summary.strip(), content=content.strip())
    yield from blog.save()  # 储存博客到数据库中
    return blog  # 返回博客信息





#json-api

@get('/api/users')
async def api_get_users():
    users = await User.findAll(orderBy = 'created_at desc')
    for u in users:
        u.passwd = '********'
    return dict(users = users)


# API:获取博客
@get('/api/blogs')
@asyncio.coroutine
def api_blogs(*, page='1'):
    page_index = get_page_index(page)
    num = yield from Blog.findNumber('count(id)') # num为博客总数
    p = Page(num, page_index)  # 创建Page对象（Page对象在apis.py中定义）
    if num == 0:
        return dict(page=p, blogs=())  # 若博客数为0,返回字典,将被app.py的response中间件再处理
    # 博客总数不为0,则从数据库中抓取博客
    # limit强制select语句返回指定的记录数,前一个参数为偏移量,后一个参数为记录的最大数目
    blogs = yield from Blog.findAll(orderBy='created_at desc', limit=(p.offset, p.limit))
    return dict(page=p, blogs=blogs)  # 返回字典,以供response中间件处理



@get('/api/blogs/{id}')
@asyncio.coroutine
def api_get_blog(*, id):
    blog = yield from Blog.find(id)
    return blog

@get('/api/comments')
@asyncio.coroutine
def api_comments(*, page='1'):
    page_index = get_page_index(page)
    num = yield from Comment.findNumber('count(id)')  # num为评论总数
    p = Page(num, page_index)  # 创建Page对象，保存页面信息
    if num == 0:
        return dict(page=p, comments=())  # 若评论数为零，返回字典，将会被app.py的response中间件再处理
    # 博客总数不为0,则从数据库中抓取博客
    # limit强制select语句返回指定的记录数,前一个参数为偏移量,后一个参数为记录的最大数目
    comments = yield from Comment.findAll(orderBy='created_at desc', limit=(p.offset, p.limit))
    return dict(page=p, comments=comments)

# API：创建评论
@post('/api/blogs/{id}/comments')
@asyncio.coroutine
def api_create_comment(id, request, *, content):
    user = request.__user__
    # 验证用户
    if user is None:
        raise APIPermissionError('Please signin first.')
    # 验证评论内容是否存在
    if not content or not content.strip():
        raise APIValueError('content')
    # 验证博客是否存在
    blog = yield from Blog.find(id)
    if blog is None:
        raise APIResourceNotFoundError('Blog')
    # 创建评论对象
    comment = Comment(blog_id=blog.id, user_id=user.id, user_name=user.name, user_image=user.image, content=content.strip())
    yield from comment.save()  # 储存评论到数据库中
    return comment  # 返回评论


# API：删除评论
@post('/api/comments/{id}/delete')
@asyncio.coroutine
def api_delete_comments(id, request):
    check_admin(request)  #查看权限，是否是管理员
    c = yield from Comment.find(id)  # 从数据库中拉去评论
    if c is None:
        raise APIResourceNotFoundError('Comment')
    yield from c.remove()  # 删除评论
    return dict(id=id)  # 返回被删除评论的id


# API:修改博客
@post('/api/blogs/{id}')
@asyncio.coroutine
def api_update_blog(id, request, *, name, summary, content):
    check_admin(request)  # 检查用户权限
    blog = yield from Blog.find(id)  # 从数据库中拉去修改前的博客
    # 检查博客的合法性
    if not name or not name.strip():
        raise APIValueError('name', 'name cannot be empty.')
    if not summary or not summary.strip():
        raise APIValueError('summary', 'summary cannot be empty.')
    if not content or not content.strip():
        raise APIValueError('content', 'content cannot be empty.')
    blog.name = name.strip()
    blog.summary = summary.strip()
    blog.content = content.strip()
    yield from blog.update()  # 更新博客
    return blog  # 返回博客信息


# API:删除博客
@post('/api/blogs/{id}/delete')
@asyncio.coroutine
def api_delete_blog(request, *, id):
    check_admin(request)
    blog = yield from Blog.find(id)
    yield from blog.remove()
    return dict(id=id)




