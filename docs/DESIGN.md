各ファイルにある関数の流れをまとめとかないと混乱しちゃうね

## プログラムでのファイルに対する命名規則
- parent_path：親ディレクトリ（例：fruit/fruit）
- path：完全パス（例：fruit/fruit/banana.txt）
- name：ファイル名（例：banana.txt）
- parent_token：親ディレクトリをハッシュでトークン化したもの
- path_token：pathをハッシュでトークン化したもの
- token：ファイル名をハッシュでトークン化したもの

## サーバ側のインデックス等の状態
/
|\_\_files/
|&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|\_\_（ファイル名（path）がハッシュ化，中身がAES）
|
|\_\_index/
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|\_\_（検索トークン（parent_pathまたはpath）がハッシュ化，中身のファイル名（name）がAES）


## ファイル内関数の流れ
サーバの処理は青で示す

### myfs.rs
#### lookup()
ファイルのinodeが存在するか確認
① parent_pathを**ハッシュ化**
② search APIを飛ばす
<font color=blue>③ サーバ側でindexディレクトリを見る，一致するものの中身を返す</font>
④ 結果がAESで返ってくる
⑤ 結果のファイルが**ファイルかディレクトリか**を判断するため，pathを**ハッシュ化**
⑥ stat APIを飛ばす
<font color=blue>⑦ サーバ側でfilesファイルを見る，pathに一致するファイルの属性を返す（rawデータ）

#### getattr()
ファイルの属性を取得
① パスを**ハッシュ化**
② stat APIを飛ばす
<font color=blue>③ サーバ側でfilesファイルを見る，pathに一致するファイルの属性を返す（rawデータ）

#### readdir()
ディレクトリ内を走査
① パスを**ハッシュ化**
② search APIを飛ばす
<font color=blue>③ サーバ側でindexディレクトリを見る，一致するものの中身を返す</font>
④ 結果がAESで返ってくる

#### create()
ファイル作成（中身なし）
① 親ディレクトリを取得，ファイル名も取得
② parent_pathを**ハッシュ化**
③ nameをAES
<font color=blue>④ サーバ側でindexディレクトリにparent_tokenとenc_nameを登録</font>
⑤ parent_path＋nameでpath生成
⑥ pathを**ハッシュ化**して，upload APIを飛ばす
<font color=blue>⑦ サーバ側でfilesディレクトリにファイルを置く</font>

#### read()
ファイルの中身を読む
① inodeからpathを取得，**トークン化**
② download APIを飛ばす
<font color=blue>③ サーバ側でfilesディレクトリを見る．pathに一致するファイルの中身を返す</font>
④ AESを復号して表示

#### write()
ファイル書き込み
① inodeからpathを取得，**トークン化**
② download APIを飛ばす
<font color=blue>③ サーバ側でfilesディレクトリを見る．pathに一致するファイルの中身を返す</font>
④ AESを復号する．
⑤ 追記するデータをAESで暗号化．ハッシュ化したpathとともにupload APIを飛ばす
<font color=blue>⑦ サーバ側でfilesディレクトリにあるファイルに追記する</font>

#### unlink()
ファイルのinodeのリンク削除
① parent_pathを**ハッシュ化**
② search APIを飛ばす
<font color=blue>③ サーバ側でindexディレクトリを見る，一致するものの中身を返す</font>
④ 結果がAESで返ってくる
⑤ 復号してたらファイル名が出てくる．nameと比較して一致するものをenc_nameとする．
⑥ parent_path，pathをそれぞれトークン化，とenc_nameを使って，delete APIを飛ばす
<font color=blue>⑦ サーバ側でfilesディレクトリのpath_tokenに一致するものを削除，
　 ＆indexディレクトリのparent_tokenに一致するファイル内の，enc_nameに一致するものを削除．
⑧ inodeも削除

echo "Hello World." > mnt/fruit/pineapple.ppa