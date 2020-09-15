const { response } = require("express");
const bcrypt = require('bcryptjs');

const Usuario = require('../models/usuario');
const { generarJwt } = require("../helpers/jwt");



const crearUsuario = async (req,res = response) => {

    const {email, password} = req.body;

    try {

        const existeEmail = await Usuario.findOne({email});
        if (existeEmail) {
            return res.status(400).json({
                ok:false,
                msg:'elcorreo ya esta registrado'
            });
        }

        const usuario = new Usuario(req.body);

        //Encriptar contraseña
        const salt = bcrypt.genSaltSync();
        usuario.password = bcrypt.hashSync(password,salt);

        //guardar en DB
        await usuario.save();

        //generar JWT
        const token = await generarJwt(usuario.id);

    

    res.json({
        ok:true,
        usuario,
        token
    });

        
    } catch (error) {
        console.log(error);
        res.status(500).json({
            ok:false,
            msg:'Hable con el administrador'
        });
    }

    
}

const login = async(req,res = response) => {

    const { email ,password} = req.body;

    try {
        const usuarioDB = await Usuario.findOne({email});
        if (!usuarioDB) {
            return res.status(404).json({
                ok:false,
                msg:'EMail no encontrado'
            });
        }

        //validar password
        const validarPassword = bcrypt.compareSync(password,usuarioDB.password);
        if (!validarPassword) {
            return res.status(404).json({
                ok:false,
                msg:'password no encontrado'
            });
        }

        // generar password
        const token = await generarJwt(usuarioDB.id);

        res.json({
            ok:true,
            usuario:usuarioDB,
            token
        });

        
    } catch (error) {
        console.log(error);
        res.status(500).json({
            ok:false,
            msg:'Hable co el admin'
        });
    }


}

const renewToken = async(req,res = response)=>{

//recuperar id autenticado
    const uid = req.uid;

   

//generando nuevo TOKEN
    const token = await generarJwt(uid);

//obteniendo en usuario de la Db
    const usuario = await Usuario.findById(uid);


    res.json({
        ok:true,
        usuario,
        token
    });

}

module.exports = {
    crearUsuario,
    login,
    renewToken
}