from flask import Flask, render_template, request, flash, send_file, redirect, url_for
from werkzeug.utils import secure_filename
import os
import shutil
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './temp'
app.secret_key = 'mykey'

@app.route('/')
def index():
    shutil.rmtree(app.config['UPLOAD_FOLDER'])
    os.makedirs(app.config['UPLOAD_FOLDER'])
    return render_template('index.html')

@app.route('/firmar', methods=['POST'])
def firmarArchivo():
    if request.method == 'POST':
        try:
            txt_virgen = request.files['plano']
            nombre_archivo_texto = secure_filename(txt_virgen.filename)
            txt_virgen.save(os.path.join(app.config['UPLOAD_FOLDER'], nombre_archivo_texto))
            llave_privada = request.files['privada']
            nombre_archivo_llave = secure_filename(llave_privada.filename)
            llave_privada.save(os.path.join(app.config['UPLOAD_FOLDER'], nombre_archivo_llave))
            
            with open(f'temp/{nombre_archivo_llave}', 'r') as f:
                privKey = RSA.import_key(f.read())
                f.close()

            with open(f'temp/{nombre_archivo_texto}', 'rb') as f:
                lista = f.readlines()
                msg = b""
                for l in lista[0:len(lista)-1]:
                    msg += l
                f.close()

            msgF = msg

            h = SHA1.new(msgF)
            firma = pkcs1_15.new(privKey).sign(h)

            with open(f'temp/{nombre_archivo_texto}','ab') as f:
                f.write(firma)
                f.close()

            response = send_file(os.path.join(app.config['UPLOAD_FOLDER'], nombre_archivo_texto), as_attachment=True)
            return response
        except:
            flash('danger')
            flash('OCURRIO UN ERROR AL SUBIR LOS ARCHIVOS, PRUEBE DE NUEVO')
            return redirect(url_for('index'))

@app.route('/verificar', methods=['POST'])
def verificarArchivo():
    if request.method == 'POST':
        try:
            txt_firmado = request.files['firmado']
            nombre_archivo_texto = secure_filename(txt_firmado.filename)
            txt_firmado.save(os.path.join(app.config['UPLOAD_FOLDER'], nombre_archivo_texto))
            llave_publica = request.files['publica']
            nombre_archivo_llave = secure_filename(llave_publica.filename)
            llave_publica.save(os.path.join(app.config['UPLOAD_FOLDER'], nombre_archivo_llave))
            
            with open(f'temp/{nombre_archivo_llave}', 'r') as f:
                pubKey = RSA.import_key(f.read())
                f.close()

            with open(f'temp/{nombre_archivo_texto}', 'rb') as f:
                lista = f.readlines()
                firma = b""
                textoPlano = b""
                i = 0
                for l in lista:
                    if b'#' in l:
                        break
                    i += 1
                for x in lista[:i]:
                    textoPlano += x
                for x in lista[i+1:]:
                    firma += x 
                f.close()

            msgV = textoPlano
            firmaV = firma

            h = SHA1.new(msgV)

            try:
                pkcs1_15.new(pubKey).verify(h,firmaV)
                flash('success')
                flash('EXITO: LA FIRMA ES VALIDA')
            except:
                flash('danger')
                flash('ADVERTENCIA: LA FIRMA NO ES VALIDA')
        except:
            flash('danger')
            flash('OCURRIO UN ERROR AL SUBIR LOS ARCHIVOS, PRUEBE DE NUEVO')
        return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)